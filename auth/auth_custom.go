package auth

import (
	"context"
	"net/http"
	"sort"

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
	//start
	// sort.Strings(ab.Config.Modules.LoginPreserveFields)
	//end

	// i.origWriter.Config.Core.Router.Get("/login", i.origWriter.Core.ErrorHandler.Wrap(a.LoginGet))
	i.origWriter.Config.Core.Router.Post("/login", i.origWriter.Core.ErrorHandler.Wrap(i.LoginPost))

	return nil
}

func hasString(arr []string, s string) bool {
	index := sort.SearchStrings(arr, s)
	if index < 0 || index >= len(arr) {
		return false
	}

	return arr[index] == s
}

func (i *AuthInterceptor) LoginPost(w http.ResponseWriter, r *http.Request) error {
	fmt.Println("===================LoginPost=====================================")
	logger := i.origWriter.RequestLogger(r)

	validatable, err := i.origWriter.Core.BodyReader.Read(PageLogin, r)
	if err != nil {
		return err
	}

	var arbitrary map[string]string
	var preserve map[string]string
	if arb, ok := validatable.(authboss.ArbitraryValuer); ok {
		fmt.Println("----------------------get Aribiratray---------------------------------")
		arbitrary = arb.GetValues()
		preserve = make(map[string]string)

		for k, v := range arbitrary {
			if hasString(i.origWriter.Config.Modules.LoginPreserveFields, k) {
				preserve[k] = v
			}
		}
	}

	fmt.Println(arbitrary)
	fmt.Println(preserve)
	fmt.Println("------------------>>>>>>...................................^^^^^^^^^^^^^^^^^^^^^^>>>>>>>>")
	//start
	if preserve["type"] == "email" {
		fmt.Println("-----------------userType is email----------------->>>>>>>>..................")
		if val, ok := preserve["email"]; !ok {
			if len(val) == 0 {
				w.WriteHeader(404)
				w.Write([]byte(`Email is require`))
			}
			fmt.Println(val)
			fmt.Println(ok)
			return nil
			//do something here
		}

	} else if preserve["type"] == "mobile" {
		fmt.Println("-----------------userType is mobile----------------->>>>>>>>..................")
		if val, ok := preserve["mobile"]; !ok {
			if len(val) == 0 {
				fmt.Println("-----------------mobile not set----------------->>>>>>>>..................")
				w.WriteHeader(404)
				w.Write([]byte(`Mobile is require`))
			}
			fmt.Println(val)
			fmt.Println(ok)
			return nil
			//do something here
		}
	}

	fmt.Println(arbitrary)
	fmt.Println(preserve)
	fmt.Println(preserve["type"])
	fmt.Println("----------------------------------------->>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<")
	//end
	// Skip validation since all the validation happens during the database lookup and
	// password check.
	creds := authboss.MustHaveUserValues(validatable)

	pid := creds.GetPID()

	//start
	customerToken := r.Header.Get("X-Consumer-ID")
	fmt.Println("=====================pid:%s=======cus_token:%s=================", pid, customerToken)
	//end

	//TODO: find type
	pidUser, err := i.origWriter.Storage.ServerCustom.Load(r.Context(), pid, customerToken, "email")
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
