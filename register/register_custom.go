package register

import (
	"context"
	"net/http"
	"sort"

	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
	"golang.org/x/crypto/bcrypt"
)

func init() {
	authboss.RegisterModule("register-custom", &Interceptor{})
}

type Interceptor struct {
	origWriter  *authboss.Authboss
	RegisterCus Register
}

func (i *Interceptor) Init(ab *authboss.Authboss) (err error) {
	i.origWriter = ab

	if _, ok := ab.Config.Storage.ServerCustom.(authboss.CreatingServerStorerCustom); !ok {
		return errors.New("register module activated but storer could not be upgraded to CreatingServerStorer")
	}

	if err := ab.Config.Core.ViewRenderer.Load(PageRegister); err != nil {
		return err
	}

	sort.Strings(ab.Config.Modules.RegisterPreserveFields)

	// ab.Config.Core.Router.Get("/register", ab.Config.Core.ErrorHandler.Wrap(i.Get))
	ab.Config.Core.Router.Post("/register", ab.Config.Core.ErrorHandler.Wrap(i.Post))

	return nil

}

func (i *Interceptor) Post(w http.ResponseWriter, req *http.Request) error {

	logger := i.origWriter.RequestLogger(req)
	validatable, err := i.origWriter.Core.BodyReader.Read(PageRegister, req)
	if err != nil {
		return err
	}

	var arbitrary map[string]string
	var preserve map[string]string
	if arb, ok := validatable.(authboss.ArbitraryValuer); ok {
		arbitrary = arb.GetValues()
		preserve = make(map[string]string)

		for k, v := range arbitrary {
			if hasString(i.origWriter.Config.Modules.RegisterPreserveFields, k) {
				preserve[k] = v
			}
		}
	}

	errs := validatable.Validate()
	if errs != nil {
		logger.Info("registration validation failed")
		data := authboss.HTMLData{
			authboss.DataValidation: authboss.ErrorMap(errs),
		}
		if preserve != nil {
			data[authboss.DataPreserve] = preserve
		}
		return i.origWriter.Config.Core.Responder.Respond(w, req, http.StatusOK, PageRegister, data)
	}

	// Get values from request
	userVals := authboss.MustHaveUserValues(validatable)
	pid, password := userVals.GetPID(), userVals.GetPassword()

	// Put values into newly created user for storage
	storer := authboss.EnsureCanCreateCus(i.origWriter.Config.Storage.ServerCustom)
	user := authboss.MustBeAuthable(storer.New(req.Context()))

	pass, err := bcrypt.GenerateFromPassword([]byte(password), i.origWriter.Config.Modules.BCryptCost)
	if err != nil {
		return err
	}

	user.PutPID(pid)
	user.PutPassword(string(pass))
	//start
	x_consumer_id := req.Header.Get("X-Consumer-ID")
	user.PutCustomerToken(string(x_consumer_id))
	//end

	if arbUser, ok := user.(authboss.ArbitraryUser); ok && arbitrary != nil {
		arbUser.PutArbitrary(arbitrary)
	}

	err = storer.Create(req.Context(), user)
	switch {
	case err == authboss.ErrUserFound:
		logger.Infof("user %s attempted to re-register", pid)
		errs = []error{errors.New("user already exists")}
		data := authboss.HTMLData{
			authboss.DataValidation: authboss.ErrorMap(errs),
		}
		if preserve != nil {
			data[authboss.DataPreserve] = preserve
		}
		return i.origWriter.Config.Core.Responder.Respond(w, req, http.StatusOK, PageRegister, data)
	case err != nil:
		return err
	}

	//start
	authboss.PutSession(w, authboss.SessionKey, pid)
	//end
	req = req.WithContext(context.WithValue(req.Context(), authboss.CTXKeyUser, user))

	roCus := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		Success:      "Account successfully created, you are now logged in",
		RedirectPath: i.origWriter.Config.Paths.RegisterOK,
		//start
		UserEmail: pid,
		//end
	}

	handled, err := i.origWriter.Events.FireAfterCustom(authboss.EventRegister, w, req, roCus)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	// Log the user in, but only if the response wasn't handled previously
	// by a module like confirm.
	authboss.PutSession(w, authboss.SessionKey, pid)

	logger.Infof("registered and logged in user %s", pid)
	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		Success:      "Account successfully created, you are now logged in",
		RedirectPath: i.origWriter.Config.Paths.RegisterOK,
		//start
		UserEmail: pid,
		//end
	}
	return i.origWriter.Config.Core.Redirector.Redirect(w, req, ro)

}
