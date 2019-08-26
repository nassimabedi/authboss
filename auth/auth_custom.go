package auth

import (
	"context"
	"net/http"

	"fmt"

	"github.com/volatiletech/authboss"
	"golang.org/x/crypto/bcrypt"
)

func init() {
	authboss.RegisterModule("auth-custom", &AuthInterceptor{})
}

type AuthInterceptor struct {
	origWriter *authboss.Authboss
	AuthCus    Auth
	// overridden bool
}

func (i *AuthInterceptor) Init(ab *authboss.Authboss) (err error) {
	// a.Authboss = ab
	i.origWriter = ab

	if err = i.origWriter.Config.Core.ViewRenderer.Load(PageLogin); err != nil {
		return err
	}

	// i.origWriter.Config.Core.Router.Get("/login", i.origWriter.Core.ErrorHandler.Wrap(a.LoginGet))
	i.origWriter.Config.Core.Router.Post("/login", i.origWriter.Core.ErrorHandler.Wrap(i.LoginPost))

	return nil
}

func (i *AuthInterceptor) LoginPost(w http.ResponseWriter, r *http.Request) error {
	fmt.Println("===================LoginPost=====================================")
	logger := i.origWriter.RequestLogger(r)

	validatable, err := i.origWriter.Core.BodyReader.Read(PageLogin, r)
	if err != nil {
		return err
	}

	// Skip validation since all the validation happens during the database lookup and
	// password check.
	creds := authboss.MustHaveUserValues(validatable)

	pid := creds.GetPID()

	//start
	customerToken := r.Header.Get("X-Consumer-ID")
	fmt.Println("=====================pid:%s=======cus_token:%s=================", pid, customerToken)
	//end

	pidUser, err := i.origWriter.Storage.ServerCustom.Load(r.Context(), pid, customerToken)
	//pidUser, err := a.Authboss.Storage.Server.Load(r.Context(), pid)
	if err == authboss.ErrUserNotFound {
		logger.Infof("failed to load user requested by pid: %s", pid)
		data := authboss.HTMLData{authboss.DataErr: "Invalid Credentials"}
		return i.origWriter.Core.Responder.Respond(w, r, http.StatusOK, PageLogin, data)
	} else if err != nil {
		return err
	}

	authUser := authboss.MustBeAuthable(pidUser)
	password := authUser.GetPassword()

	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, pidUser))

	var handled bool
	err = bcrypt.CompareHashAndPassword([]byte(password), []byte(creds.GetPassword()))
	if err != nil {
		handled, err = i.origWriter.Events.FireAfter(authboss.EventAuthFail, w, r)
		if err != nil {
			return err
		} else if handled {
			return nil
		}

		logger.Infof("user %s failed to log in", pid)
		data := authboss.HTMLData{authboss.DataErr: "Invalid Credentials"}
		return i.origWriter.Core.Responder.Respond(w, r, http.StatusOK, PageLogin, data)
	}

	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyValues, validatable))

	handled, err = i.origWriter.Events.FireBefore(authboss.EventAuth, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	handled, err = i.origWriter.Events.FireBefore(authboss.EventAuthHijack, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	logger.Infof("user %s logged in", pid)
	authboss.PutSession(w, authboss.SessionKey, pid)
	authboss.DelSession(w, authboss.SessionHalfAuthKey)

	handled, err = i.origWriter.Events.FireAfter(authboss.EventAuth, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	ro := authboss.RedirectOptions{
		Code:             http.StatusTemporaryRedirect,
		RedirectPath:     i.origWriter.Paths.AuthLoginOK,
		FollowRedirParam: true,
		UserEmail:        pid,
	}
	return i.origWriter.Core.Redirector.Redirect(w, r, ro)
}
