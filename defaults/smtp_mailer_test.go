package defaults

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/smtp"
	"testing"

	// "fmt"

	"github.com/volatiletech/authboss"
)

var (
	// flagTestSMTPMailer = flag.Bool("test-smtp-mailer", false, "Test the smtp mailer")
	flagTestSMTPMailer = flag.Bool("test-smtp-mailer", true, "Test the smtp mailer")
)

type unencryptedAuth struct {
	smtp.Auth
}

func (a unencryptedAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	s := *server
	s.TLS = true
	return a.Auth.Start(&s)
}

func TestSMTPMailer(t *testing.T) {
	t.Parallel()
	t.Log("================hi===============")

	if !*flagTestSMTPMailer {
		t.Skip("SMTP Mailer Testing not enabled (-test-smtp-mailer flag)")
	}

	creds := struct {
		Server   string `json:"server,omitempty"`
		Port     int    `json:"port,omitempty"`
		Email    string `json:"email,omitempty"`
		Password string `json:"password,omitempty"`
	}{}

	b, err := ioutil.ReadFile("smtp_mailer_test.json")
	if err != nil {
		t.Fatal(`error reading file: "smtp_mailer_test.json`, err)
	}

	if err = json.Unmarshal(b, &creds); err != nil {
		t.Fatal(err)
	}
	fmt.Println("===========hi========================")

	//server := fmt.Sprintf("%s:%d", creds.Server, creds.Port)
	//mailer := NewSMTPMailer(server, smtp.PlainAuth("", creds.Email, creds.Password, creds.Server))

	server := fmt.Sprintf("%s:%d", creds.Server, creds.Port)
	//mailer := NewSMTPMailer(server, smtp.PlainAuth("", creds.Email, creds.Password, creds.Server))
	auth := unencryptedAuth{
		smtp.PlainAuth(
			"",
			"confirm@manam.ir",
			"Conf1010",
			"smtp.manam.ir",
		),
	}
	//  mailer := NewSMTPMailer(server, smtp.PlainAuth("", "confirm@manam.ir", "Conf1010", "smtp.manam.ir"))
	mailer := NewSMTPMailer(server, auth)

	//mail := authboss.Email{
	//	From:    creds.Email,
	//	To:      []string{creds.Email},
	//	Subject: "Authboss Test SMTP Mailer",
	//}

	mail := authboss.Email{
		From:    creds.Email,
		To:      []string{"nassimabedi@gmail.com"},
		Subject: "Authboss Test SMTP Mailer",
	}

	txtOnly := mail
	txtOnly.Subject += ": Text Content"
	txtOnly.TextBody = "Authboss\nSMTP\nTest\nWith\nNewlines"

	if err = mailer.Send(context.Background(), txtOnly); err != nil {
		t.Log("---------------------Email mot send :P -----")
		t.Error(err)
	}

	htmlOnly := mail
	htmlOnly.Subject += ": HTML Content"
	htmlOnly.HTMLBody = "Authboss<br>Test<br>\nWith<br>Newlines\nand<br>breaks"

	if err = mailer.Send(context.Background(), htmlOnly); err != nil {
		t.Error(err)
	}

	mixed := mail
	mixed.Subject += ": Mixed Content"
	mixed.HTMLBody = htmlOnly.HTMLBody
	mixed.TextBody = txtOnly.TextBody

	if err = mailer.Send(context.Background(), mixed); err != nil {
		t.Error(err)
	}
}

func TestSMTPMailerPanic(t *testing.T) {
	t.Parallel()

	_ = NewSMTPMailer("server", nil)

	recovered := false
	defer func() {
		recovered = recover() != nil
	}()

	NewSMTPMailer("", nil)

	if !recovered {
		t.Error("Should have panicked.")
	}
}
