package home

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghuser"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"golang.org/x/crypto/bcrypt"
)

// webUser represents a user of the Web UI.
type webUser struct {
	// Name represents the login name of the web user.
	Name string `yaml:"name"`

	// PasswordHash is the hashed representation of the web user password.
	PasswordHash string `yaml:"password"`

	// UserID is the unique identifier of the web user.
	//
	// TODO(s.chzhen): !! Use this.
	UserID aghuser.UserID `yaml:"-"`
}

// toUser returns the new properly initialized *aghuser.User using stored
// properties.  It panics if there is an error generating the user ID.
func (wu *webUser) toUser() (u *aghuser.User) {
	uid := wu.UserID
	if uid == (aghuser.UserID{}) {
		uid = aghuser.MustNewUserID()
	}

	return &aghuser.User{
		Password: aghuser.NewDefaultPassword(wu.PasswordHash),
		Login:    aghuser.Login(wu.Name),
		ID:       uid,
	}
}

// Auth is the global authentication object.
type Auth struct {
	logger         *slog.Logger
	rateLimiter    *authRateLimiter
	sessions       aghuser.SessionStorage
	trustedProxies netutil.SubnetSet
	users          aghuser.DB
}

// InitAuth initializes the global authentication object.  baseLogger,
// rateLimiter, trustedProxies must not be nil.  dbFilename and sessionTTL
// should not be empty.
func InitAuth(
	ctx context.Context,
	baseLogger *slog.Logger,
	dbFilename string,
	users []webUser,
	sessionTTL time.Duration,
	rateLimiter *authRateLimiter,
	trustedProxies netutil.SubnetSet,
) (a *Auth, err error) {
	userDB := aghuser.NewDefaultDB()
	for i, u := range users {
		err = userDB.Create(ctx, u.toUser())
		if err != nil {
			return nil, fmt.Errorf("users: at index %d: %w", i, err)
		}
	}

	s, err := aghuser.NewDefaultSessionStorage(ctx, &aghuser.DefaultSessionStorageConfig{
		Logger:     baseLogger.With(slogutil.KeyPrefix, "session_storage"),
		Clock:      timeutil.SystemClock{},
		UserDB:     aghuser.NewDefaultDB(),
		DBPath:     dbFilename,
		SessionTTL: sessionTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("creating session storage: %w", err)
	}

	return &Auth{
		logger:         baseLogger.With(slogutil.KeyPrefix, "auth"),
		rateLimiter:    rateLimiter,
		trustedProxies: trustedProxies,
		sessions:       s,
		users:          userDB,
	}, nil
}

// Close closes the authentication database.
func (a *Auth) Close(ctx context.Context) {
	err := a.sessions.Close()
	if err != nil {
		a.logger.ErrorContext(ctx, "closing session storage", slogutil.KeyError, err)
	}
}

// isValidSession returns true if the session is valid.
func (a *Auth) isValidSession(ctx context.Context, cookieSess string) (ok bool) {
	sess, err := hex.DecodeString(cookieSess)
	if err != nil {
		a.logger.ErrorContext(ctx, "checking session: decoding cookie", slogutil.KeyError, err)

		return false
	}

	var t aghuser.SessionToken
	copy(t[:], sess)

	s, err := a.sessions.FindByToken(ctx, t)
	if err != nil {
		a.logger.ErrorContext(ctx, "checking session", slogutil.KeyError, err)

		return false
	}

	return s != nil
}

// addUser adds a new user with the given password.  u must not be nil.
func (a *Auth) addUser(ctx context.Context, u *webUser, password string) (err error) {
	if len(password) == 0 {
		return errors.Error("empty password")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("generating hash: %w", err)
	}

	u.PasswordHash = string(hash)

	err = a.users.Create(ctx, u.toUser())
	if err != nil {
		// Should not happen.
		panic(err)
	}

	a.logger.DebugContext(ctx, "added user", "login", u.Name)

	return nil
}

// findUser returns a user if one exists with the provided login and the
// password matches.
func (a *Auth) findUser(ctx context.Context, login, password string) (user *aghuser.User) {
	user, err := a.users.ByLogin(ctx, aghuser.Login(login))
	if err != nil {
		return nil
	}

	ok := user.Password.Authenticate(ctx, password)
	if !ok {
		return nil
	}

	return user
}

// getCurrentUser searches for a user using a cookie or credentials from basic
// authentication.
func (a *Auth) getCurrentUser(r *http.Request) (user *aghuser.User) {
	ctx := r.Context()
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		// There's no Cookie, check Basic authentication.
		user, pass, ok := r.BasicAuth()
		if ok {
			return a.findUser(ctx, user, pass)
		}

		return nil
	}

	sess, err := hex.DecodeString(cookie.Value)
	if err != nil {
		a.logger.ErrorContext(
			ctx,
			"searching for user: decoding cookie value",
			slogutil.KeyError, err,
		)

		return nil
	}

	var t aghuser.SessionToken
	copy(t[:], sess)

	s, err := a.sessions.FindByToken(ctx, t)
	if err != nil {
		a.logger.ErrorContext(ctx, "searching for user", slogutil.KeyError, err)

		return nil
	}

	if s == nil {
		return nil
	}

	return &aghuser.User{
		Login: s.UserLogin,
		ID:    s.UserID,
	}
}

// removeSession deletes the session from the active sessions and the disk.  It
// also logs any occurring errors.
func (a *Auth) removeSession(ctx context.Context, cookieSess string) {
	sess, err := hex.DecodeString(cookieSess)
	if err != nil {
		a.logger.ErrorContext(ctx, "removing session: decoding cookie", slogutil.KeyError, err)

		return
	}

	var t aghuser.SessionToken
	copy(t[:], sess)

	err = a.sessions.DeleteByToken(ctx, t)
	if err != nil {
		a.logger.ErrorContext(ctx, "removing session by token", slogutil.KeyError, err)
	}
}

// usersList returns a copy of a users list.
func (a *Auth) usersList(ctx context.Context) (webUsers []webUser) {
	users, err := a.users.All(ctx)
	if err != nil {
		// Should not happen.
		panic(err)
	}

	webUsers = make([]webUser, 0, len(users))
	for _, u := range users {
		webUsers = append(webUsers, webUser{
			Name:         string(u.Login),
			PasswordHash: string(u.Password.Hash()),
			UserID:       u.ID,
		})
	}

	return webUsers
}

// authRequired returns true if a authentication is required.
func (a *Auth) authRequired(ctx context.Context) (ok bool) {
	if GLMode {
		return true
	}

	users, err := a.users.All(ctx)
	if err != nil {
		// Should not happen.
		panic(err)
	}

	return len(users) != 0
}
