package recover

import (
	"context"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/volatiletech/authboss"
	"golang.org/x/crypto/bcrypt"
)

func init() {
	authboss.RegisterModule("recover-custom", &RecoverInterceptor{})
}

type RecoverInterceptor struct {
	origWriter *authboss.Authboss
	RecoverCus Recover
	// overridden bool
}

func (i *RecoverInterceptor) Init(ab *authboss.Authboss) (err error) {
	i.origWriter = ab

	if err := i.origWriter.Config.Core.ViewRenderer.Load(PageRecoverStart, PageRecoverEnd); err != nil {
		return err
	}

	if err := i.origWriter.Config.Core.MailRenderer.Load(EmailRecoverHTML, EmailRecoverTxt); err != nil {
		return err
	}

	// i.origWriter.Config.Core.Router.Get("/recover", i.origWriter.Core.ErrorHandler.Wrap(r.StartGet))
	i.origWriter.Config.Core.Router.Post("/recover", i.origWriter.Core.ErrorHandler.Wrap(i.StartPost))
	// i.origWriter.Config.Core.Router.Get("/recover/end", i.origWriter.Core.ErrorHandler.Wrap(r.EndGet))
	i.origWriter.Config.Core.Router.Post("/recover/end", i.origWriter.Core.ErrorHandler.Wrap(i.EndPost))

	return nil
}

func (i *RecoverInterceptor) StartPost(w http.ResponseWriter, req *http.Request) error {
	fmt.Println("--------------------------override recover--------------------------------------")
	logger := i.origWriter.RequestLogger(req)

	validatable, err := i.origWriter.Core.BodyReader.Read(PageRecoverStart, req)
	if err != nil {
		return err
	}

	if errs := validatable.Validate(); errs != nil {
		logger.Info("recover validation failed")
		data := authboss.HTMLData{authboss.DataValidation: authboss.ErrorMap(errs)}
		return i.origWriter.Core.Responder.Respond(w, req, http.StatusOK, PageRecoverStart, data)
	}

	recoverVals := authboss.MustHaveRecoverStartValues(validatable)

	//start
	fmt.Println("========================================>>>>>>>>>>>>>>>>>>>>>>-----------------1111")

	customerToken := req.Header.Get("X-Consumer-ID")
	fmt.Println(recoverVals)
	fmt.Println(recoverVals.GetPID())
	fmt.Println(recoverVals.GetUserType())

	fmt.Println("========================================>>>>>>>>>>>>>>>>>>>>>>-----------------22222")
	//end

	user, err := i.origWriter.Storage.ServerCustom.Load(req.Context(), recoverVals.GetPID(), customerToken, recoverVals.GetUserType())
	if err == authboss.ErrUserNotFound {
		//TODO: has error when user not found
		fmt.Println("--------------------------error found 11111111--------------------------------------")
		logger.Infof("user %s was attempted to be recovered, user does not exist, faking successful response", recoverVals.GetPID())
		ro := authboss.RedirectOptions{
			Code:         http.StatusTemporaryRedirect,
			RedirectPath: i.origWriter.Config.Paths.RecoverOK,
			Success:      recoverInitiateSuccessFlash,
		}
		return i.origWriter.Core.Redirector.Redirect(w, req, ro)
	}

	ru := authboss.MustBeRecoverable(user)

	selector, verifier, token, err := GenerateRecoverCreds()
	if err != nil {
		return err
	}

	ru.PutRecoverSelector(selector)
	ru.PutRecoverVerifier(verifier)
	ru.PutRecoverExpiry(time.Now().UTC().Add(i.origWriter.Config.Modules.RecoverTokenDuration))

	if err := i.origWriter.Storage.ServerCustom.Save(req.Context(), ru); err != nil {
		return err
	}

	// goRecoverEmail(i.RecoverCus, req.Context(), ru.GetEmail(), token)
	goRecoverEmailCus(i, req.Context(), ru.GetEmail(), token)

	logger.Infof("user %s password recovery initiated", ru.GetPID())
	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: i.origWriter.Config.Paths.RecoverOK,
		Success:      recoverInitiateSuccessFlash,
	}
	return i.origWriter.Core.Redirector.Redirect(w, req, ro)
}

var goRecoverEmailCus = func(i *RecoverInterceptor, ctx context.Context, to, encodedToken string) {
	i.SendRecoverEmailCus(ctx, to, encodedToken)
}

// SendRecoverEmail to a specific e-mail address passing along the encodedToken
// in an escaped URL to the templates.
func (i *RecoverInterceptor) SendRecoverEmailCus(ctx context.Context, to, encodedToken string) {
	logger := i.origWriter.Logger(ctx)

	// mailURL := i.RecoverCus.mailURL(encodedToken)
	mailURL := i.mailURL(encodedToken)

	email := authboss.Email{
		To:       []string{to},
		From:     i.origWriter.Config.Mail.From,
		FromName: i.origWriter.Config.Mail.FromName,
		Subject:  i.origWriter.Config.Mail.SubjectPrefix + "Password Reset",
	}

	ro := authboss.EmailResponseOptions{
		HTMLTemplate: EmailRecoverHTML,
		TextTemplate: EmailRecoverTxt,
		Data: authboss.HTMLData{
			DataRecoverURL: mailURL,
		},
	}

	logger.Infof("sending recover e-mail to: %s", to)
	if err := i.origWriter.Email(ctx, email, ro); err != nil {
		logger.Errorf("failed to recover send e-mail to %s: %+v", to, err)
	}
}

func (i *RecoverInterceptor) mailURL(token string) string {
	query := url.Values{FormValueToken: []string{token}}

	if len(i.origWriter.Config.Mail.RootURL) != 0 {
		return fmt.Sprintf("%s?%s", i.origWriter.Config.Mail.RootURL+"/recover/end", query.Encode())
	}

	p := path.Join(i.origWriter.Config.Paths.Mount, "recover/end")
	return fmt.Sprintf("%s%s?%s", i.origWriter.Config.Paths.RootURL, p, query.Encode())
}

// // EndGet shows a password recovery form, and it should have the token that
// // the user brought in the query parameters in it on submission.
// func (r *Recover) EndGet(w http.ResponseWriter, req *http.Request) error {
// 	validatable, err := r.Authboss.Core.BodyReader.Read(PageRecoverMiddle, req)
// 	if err != nil {
// 		return err
// 	}

// 	values := authboss.MustHaveRecoverMiddleValues(validatable)
// 	token := values.GetToken()

// 	data := authboss.HTMLData{
// 		DataRecoverToken: token,
// 	}

// 	return r.Authboss.Config.Core.Responder.Respond(w, req, http.StatusOK, PageRecoverEnd, data)
// }

// EndPost retrieves the token
func (i *RecoverInterceptor) EndPost(w http.ResponseWriter, req *http.Request) error {
	fmt.Println("================== override recover End POST =====================================")
	//TODO : added access token in responder
	logger := i.origWriter.RequestLogger(req)

	validatable, err := i.origWriter.Core.BodyReader.Read(PageRecoverEnd, req)
	if err != nil {
		return err
	}

	values := authboss.MustHaveRecoverEndValues(validatable)
	password := values.GetPassword()
	token := values.GetToken()

	if errs := validatable.Validate(); errs != nil {
		logger.Info("recovery validation failed")
		data := authboss.HTMLData{
			authboss.DataValidation: authboss.ErrorMap(errs),
			DataRecoverToken:        token,
		}
		return i.origWriter.Config.Core.Responder.Respond(w, req, http.StatusOK, PageRecoverEnd, data)
	}

	rawToken, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		logger.Infof("invalid recover token submitted, base64 decode failed: %+v", err)
		return i.invalidToken(PageRecoverEnd, w, req)
	}

	if len(rawToken) != recoverTokenSize {
		logger.Infof("invalid recover token submitted, size was wrong: %d", len(rawToken))
		return i.invalidToken(PageRecoverEnd, w, req)
	}

	selectorBytes := sha512.Sum512(rawToken[:recoverTokenSplit])
	verifierBytes := sha512.Sum512(rawToken[recoverTokenSplit:])
	selector := base64.StdEncoding.EncodeToString(selectorBytes[:])

	fmt.Println("----------------selector:%s-----------------", selector)
	bb := req.Header.Get("X-Consumer-ID")

	// storer := authboss.EnsureCanRecover(r.Authboss.Config.Storage.Server)
	storer := authboss.EnsureCanRecoverCus(i.origWriter.Config.Storage.ServerCustom)
	user, err := storer.LoadByRecoverSelector(req.Context(), selector, bb)
	if err == authboss.ErrUserNotFound {
		logger.Info("invalid recover token submitted, user not found")
		return i.invalidToken(PageRecoverEnd, w, req)
	} else if err != nil {
		return err
	}

	if time.Now().UTC().After(user.GetRecoverExpiry()) {
		logger.Infof("invalid recover token submitted, already expired: %+v", err)
		// return i.RecoverCus.invalidToken(PageRecoverEnd, w, req)
		return i.invalidToken(PageRecoverEnd, w, req)
	}

	dbVerifierBytes, err := base64.StdEncoding.DecodeString(user.GetRecoverVerifier())
	if err != nil {
		logger.Infof("invalid recover verifier stored in database: %s", user.GetRecoverVerifier())
		// return i.RecoverCus.invalidToken(PageRecoverEnd, w, req)
		return i.invalidToken(PageRecoverEnd, w, req)
	}

	if subtle.ConstantTimeEq(int32(len(verifierBytes)), int32(len(dbVerifierBytes))) != 1 ||
		subtle.ConstantTimeCompare(verifierBytes[:], dbVerifierBytes) != 1 {
		logger.Info("stored recover verifier does not match provided one")
		// return i.RecoverCus.invalidToken(PageRecoverEnd, w, req)
		return i.invalidToken(PageRecoverEnd, w, req)
	}

	pass, err := bcrypt.GenerateFromPassword([]byte(password), i.origWriter.Config.Modules.BCryptCost)
	if err != nil {
		return err
	}

	user.PutPassword(string(pass))
	user.PutRecoverSelector("")             // Don't allow another recovery
	user.PutRecoverVerifier("")             // Don't allow another recovery
	user.PutRecoverExpiry(time.Now().UTC()) // Put current time for those DBs that can't handle 0 time

	if err := storer.Save(req.Context(), user); err != nil {
		return err
	}

	successMsg := "Successfully updated password"
	if i.origWriter.Config.Modules.RecoverLoginAfterRecovery {
		authboss.PutSession(w, authboss.SessionKey, user.GetPID())
		successMsg += " and logged in"
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: i.origWriter.Config.Paths.RecoverOK,
		Success:      successMsg,
	}
	return i.origWriter.Config.Core.Redirector.Redirect(w, req, ro)
}

func (i *RecoverInterceptor) invalidToken(page string, w http.ResponseWriter, req *http.Request) error {
	errors := []error{errors.New("recovery token is invalid")}
	data := authboss.HTMLData{authboss.DataValidation: authboss.ErrorMap(errors)}
	return i.origWriter.Core.Responder.Respond(w, req, http.StatusOK, PageRecoverEnd, data)
}
