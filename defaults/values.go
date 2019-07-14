package defaults

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"

	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"

	"fmt"
)

// FormValue types
const (
	FormValueEmail    = "email"
	FormValuePassword = "password"
	FormValueUsername = "username"

	FormValueConfirm      = "cnf"
	FormValueToken        = "token"
	FormValueCode         = "code"
	FormValueRecoveryCode = "recovery_code"
	FormValuePhoneNumber  = "phone_number"
	//start
	FormValueCustomerToken = "customer_token"
	//end
)

// UserValues from the login form
type UserValues struct {
	HTTPFormValidator

	PID           string
	Password      string
	CustomerToken string

	Arbitrary map[string]string
}

// GetPID from the values
func (u UserValues) GetPID() string {
	return u.PID
}

// GetPassword from the values
func (u UserValues) GetPassword() string {
	fmt.Println(".................PPPPPPPPPPPPPPPPPPPPPPPP....................")
	return u.Password
}

//start
// GetPassword from the values
func (u UserValues) GetCustomerToken() string {
	// return u.CustomerToken
	return "kiss_customer"
}

//end

// GetValues from the form.
func (u UserValues) GetValues() map[string]string {
	return u.Arbitrary
}

// GetShouldRemember checks the form values for
func (u UserValues) GetShouldRemember() bool {
	rm, ok := u.Values[authboss.CookieRemember]
	return ok && rm == "true"
}

// ConfirmValues retrieves values on the confirm page.
type ConfirmValues struct {
	HTTPFormValidator

	Token string
	//start
	CustomerToken string
	//end
}

// GetToken from the confirm values
func (c ConfirmValues) GetToken() string {
	return c.Token
}

//start
func (c ConfirmValues) GetCustomerToken() string {
	return c.CustomerToken
}

//end

// RecoverStartValues for recover_start page
type RecoverStartValues struct {
	HTTPFormValidator

	PID string
}

// GetPID for recovery
func (r RecoverStartValues) GetPID() string { return r.PID }

// RecoverMiddleValues for recover_middle page
type RecoverMiddleValues struct {
	HTTPFormValidator

	Token string
}

// GetToken for recovery
func (r RecoverMiddleValues) GetToken() string { return r.Token }

// RecoverEndValues for recover_end page
type RecoverEndValues struct {
	HTTPFormValidator

	Token       string
	NewPassword string
}

// GetToken for recovery
func (r RecoverEndValues) GetToken() string { return r.Token }

// GetPassword for recovery
func (r RecoverEndValues) GetPassword() string { return r.NewPassword }

// TwoFA for totp2fa_validate page
type TwoFA struct {
	HTTPFormValidator

	Code         string
	RecoveryCode string
}

// GetCode from authenticator
func (t TwoFA) GetCode() string { return t.Code }

// GetRecoveryCode for authenticator
func (t TwoFA) GetRecoveryCode() string { return t.RecoveryCode }

// SMSTwoFA for sms2fa_validate page
type SMSTwoFA struct {
	HTTPFormValidator

	Code         string
	RecoveryCode string
	PhoneNumber  string
}

// GetCode from sms
func (s SMSTwoFA) GetCode() string { return s.Code }

// GetRecoveryCode from sms
func (s SMSTwoFA) GetRecoveryCode() string { return s.RecoveryCode }

// GetPhoneNumber from authenticator
func (s SMSTwoFA) GetPhoneNumber() string { return s.PhoneNumber }

// HTTPBodyReader reads forms from various pages and decodes
// them.
type HTTPBodyReader struct {
	// ReadJSON if turned on reads json from the http request
	// instead of a encoded form.
	ReadJSON bool

	// UseUsername instead of e-mail address
	UseUsername bool

	// Rulesets for each page.
	Rulesets map[string][]Rules
	// Confirm fields for each page.
	Confirms map[string][]string
	// Whitelist values for each page through the html forms
	// this is for security so that we can properly protect the
	// arbitrary user API. In reality this really only needs to be set
	// for the register page since everything else is expecting
	// a hardcoded set of values.
	Whitelist map[string][]string
}

// NewHTTPBodyReader creates a form reader with default validation rules
// and fields for each page. If no defaults are required, simply construct
// this using the struct members itself for more control.
func NewHTTPBodyReader(readJSON, useUsernameNotEmail bool) *HTTPBodyReader {
	fmt.Println("-------------------------NewHTTPBodyReader --------------------------------")
	var pid string
	var pidRules Rules

	if useUsernameNotEmail {
		pid = "username"
		pidRules = Rules{
			FieldName: pid, Required: true,
			MatchError: "Usernames must only start with letters, and contain letters and numbers",
			MustMatch:  regexp.MustCompile(`(?i)[a-z][a-z0-9]?`),
		}
	} else {
		pid = "email"
		pidRules = Rules{
			FieldName: pid, Required: true,
			MatchError: "Must be a valid e-mail address",
			MustMatch:  regexp.MustCompile(`.*@.*\.[a-z]{1,}`),
		}
	}

	passwordRule := Rules{
		FieldName:  "password",
		MinLength:  8,
		MinNumeric: 1,
		MinSymbols: 1,
		MinUpper:   1,
		MinLower:   1,
	}

	return &HTTPBodyReader{
		UseUsername: useUsernameNotEmail,
		ReadJSON:    readJSON,
		Rulesets: map[string][]Rules{
			"login":         {pidRules},
			"register":      {pidRules, passwordRule},
			"confirm":       {Rules{FieldName: FormValueConfirm, Required: true}},
			"recover_start": {pidRules},
			"recover_end":   {passwordRule},

			"twofactor_verify_end": {Rules{FieldName: FormValueToken, Required: true}},
		},
		Confirms: map[string][]string{
			"register":    {FormValuePassword, authboss.ConfirmPrefix + FormValuePassword},
			"recover_end": {FormValuePassword, authboss.ConfirmPrefix + FormValuePassword},
		},
		Whitelist: map[string][]string{
			"register": []string{FormValueEmail, FormValuePassword},
		},
	}
}

// Read the form pages
func (h HTTPBodyReader) Read(page string, r *http.Request) (authboss.Validator, error) {
	//start
	fmt.Println("--------------------------Read-----------------------------------^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^----------------------:))))))))))")
	aa := r.Header.Get("User-Agent")
	fmt.Printf("----------user-agent:%s-----------\n", aa)
	bb := r.Header.Get("customer_token")
	fmt.Printf("----------customer_token:%s-----------\n", bb)
	method := r.URL.Path

	if len(bb) == 0 {
		//return nil, errors.Errorf("failed to set customer token in method : %s",method)
		//return nil, errors.Wrap( new error,"failed to set customer token in header")
		fmt.Printf("=========method:%s==========",method)
	}
	//end
	var values map[string]string

	if h.ReadJSON {
		b, err := ioutil.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return nil, errors.Wrap(err, "failed to read http body")
		}

		if err = json.Unmarshal(b, &values); err != nil {
			return nil, errors.Wrap(err, "failed to parse json http body")
		}
	} else {
		if err := r.ParseForm(); err != nil {
			return nil, errors.Wrapf(err, "failed to parse form on page: %s", page)
		}
		values = URLValuesToMap(r.Form)
	}

	rules := h.Rulesets[page]
	confirms := h.Confirms[page]
	whitelist := h.Whitelist[page]

	switch page {
	case "confirm":
		return ConfirmValues{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules},
			Token:             values[FormValueConfirm],
			// CustomerToken:     values[FormValueCustomerToken],
			CustomerToken: bb,
		}, nil
	case "login":
		var pid string
		if h.UseUsername {
			pid = values[FormValueUsername]
		} else {
			pid = values[FormValueEmail]
		}

		return UserValues{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules, ConfirmFields: confirms},
			PID:               pid,
			Password:          values[FormValuePassword],
			// CustomerToken:     values[FormValueCustomerToken],
			CustomerToken:     bb,
		}, nil
	case "recover_start":
		var pid string
		if h.UseUsername {
			pid = values[FormValueUsername]
		} else {
			pid = values[FormValueEmail]
		}

		return RecoverStartValues{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules, ConfirmFields: confirms},
			PID:               pid,
		}, nil
	case "recover_middle":
		return RecoverMiddleValues{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules, ConfirmFields: confirms},
			Token:             values[FormValueToken],
		}, nil
	case "recover_end":
		return RecoverEndValues{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules, ConfirmFields: confirms},
			Token:             values[FormValueToken],
			NewPassword:       values[FormValuePassword],
		}, nil
	case "twofactor_verify_end":
		// Reuse ConfirmValues here, it's the same values we need
		return ConfirmValues{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules, ConfirmFields: confirms},
			Token:             values[FormValueToken],
		}, nil
	case "totp2fa_confirm", "totp2fa_remove", "totp2fa_validate":
		return TwoFA{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules, ConfirmFields: confirms},
			Code:              values[FormValueCode],
			RecoveryCode:      values[FormValueRecoveryCode],
		}, nil
	case "sms2fa_setup", "sms2fa_remove", "sms2fa_confirm", "sms2fa_validate":
		return SMSTwoFA{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules, ConfirmFields: confirms},
			Code:              values[FormValueCode],
			PhoneNumber:       values[FormValuePhoneNumber],
			RecoveryCode:      values[FormValueRecoveryCode],
		}, nil
	case "register":
		arbitrary := make(map[string]string)

		for k, v := range values {
			for _, w := range whitelist {
				if k == w {
					arbitrary[k] = v
					break
				}
			}
		}

		var pid string
		if h.UseUsername {
			pid = values[FormValueUsername]
		} else {
			pid = values[FormValueEmail]
		}

		return UserValues{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules, ConfirmFields: confirms},
			PID:               pid,
			Password:          values[FormValuePassword],
			//start
			CustomerToken: bb,
			//end
			Arbitrary: arbitrary,
		}, nil
	default:
		return nil, errors.Errorf("failed to parse unknown page's form: %s", page)
	}
}

// URLValuesToMap helps create a map from url.Values
func URLValuesToMap(form url.Values) map[string]string {
	fmt.Println("-----------------URLValuesToMap--------------------------------------")
	values := make(map[string]string)

	for k, v := range form {
		if len(v) != 0 {
			values[k] = v[0]
		}
	}

	return values
}
