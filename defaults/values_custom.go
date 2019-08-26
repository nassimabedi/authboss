package defaults

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
)

// type DefaultsInterceptor struct {
// 	origWriter &Read
// 	overridden bool
// }

type UserValuesCus struct {
	// UserValues
	HTTPFormValidator

	PID      string
	Password string
	// CustomerToken string

	Arbitrary     map[string]string
	CustomerToken string
}

type ConfirmValuesCus struct {
	HTTPFormValidator

	Token string
	//start
	// CustomerToken string
	//end
	//start
	CustomerToken string
	//end
}

//start
func (c ConfirmValuesCus) GetCustomerToken() string {
	return c.CustomerToken
}

func (u UserValuesCus) GetCustomerToken() string {
	return u.CustomerToken
	// return "kiss_customer"
}

// func (UserValues) Call() {
// 	fmt.Println("Foo Called")
// 	CustomerToken string
// }

// type HTTPBodyReaderCus struct {
// 	HTTPBodyReader
// }

// func (i *DefaultsInterceptor) Read(page string, r *http.Request) {
// 	switch rc {
// 	case 500:
// 		http.Error(i.origWriter, "Custom 500 message / content", 500)
// 	case 404:
// 		http.Error(i.origWriter, "Custom 404 message", 404)
// 	case 403:
// 		i.origWriter.WriteHeader(403)
// 		fmt.Fprintln(i.origWriter, "Custom 403 message")
// 	default:
// 		i.origWriter.WriteHeader(rc)
// 		return
// 	}
// 	// if the default case didn't execute (and return) we must have overridden the output
// 	i.overridden = true
// 	log.Println(i.overridden)
// }

func (h HTTPBodyReader) ReadCus(page string, r *http.Request) (authboss.Validator, error) {
	//start
	fmt.Println("------------------override--------Read-----------------------------------^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^----------------------:))))))))))*******")
	aa := r.Header.Get("User-Agent")
	fmt.Printf("----------user-agent:%s-----------\n", aa)
	//bb := r.Header.Get("customer_token")
	bb := r.Header.Get("X-Consumer-ID")
	fmt.Printf("----------customer_token:%s-----------\n", bb)
	method := r.URL.Path

	if len(bb) == 0 {
		//return nil, errors.Errorf("failed to set customer token in method : %s",method)
		//return nil, errors.Wrap( new error,"failed to set customer token in header")
		fmt.Printf("=========method:%s==========", method)
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
		return ConfirmValuesCus{
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

		return UserValuesCus{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules, ConfirmFields: confirms},
			PID:               pid,
			Password:          values[FormValuePassword],
			// CustomerToken:     values[FormValueCustomerToken],
			CustomerToken: bb,
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
		fmt.Println("-------------------------override register----------------------------")
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

		return UserValuesCus{
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
