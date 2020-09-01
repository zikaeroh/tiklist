package main

import (
	"log"
	"net/http"
	"text/template"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/zikaeroh/tiklist/internal/providers"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Compress(5))

	for name, p := range lists {
		r.Get("/"+name+".rsc", providerHandler(name, p))
	}

	log.Fatal(http.ListenAndServe(":5000", r))
}

var lists = map[string]*providers.Provider{
	"spamhaus_drop":    providers.SpamhausDROP,
	"spamhaus_edrop":   providers.SpamhausEDROP,
	"emerging_threats": providers.EmergingThreats,
	"okean":            providers.Okean,
	"myip":             providers.MyIP,
	"dshield":          providers.DShield,
}

var tmpl = template.Must(template.New("tmpl.rsc").Parse(`# {{.Name}}.rsc
# Generated from {{.URL}}
# At {{.Now}}

:local log do={ :put $t; :log warning $t }
$log t="Beginning {{.Name}} list update."

:local cl [ /system logging get number=0 value-name=topics ]
/system logging set numbers=0 topics="info,!firewall"

:do { /ip firewall address-list remove [find where list={{.Name}}] } on-error={}
:local i do={ /ip firewall address-list add timeout="{{.Timeout}}" list={{.Name}} address="$a" } on-error={}

{{ range $i, $a := .List }}$i a={{$a}}
{{ end }}
/system logging set numbers=0 topics=$cl
$log t="Finished {{.Name}} list update."
`))

type tmplContext struct {
	Name    string
	URL     string
	Now     string
	Timeout string
	List    []string
}

func providerHandler(listName string, p *providers.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		list, err := p.List(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		timeout := r.FormValue("timeout")
		if timeout == "" {
			timeout = "25h"
		}

		_ = tmpl.Execute(w, &tmplContext{
			Name:    listName,
			URL:     p.URL(),
			Now:     time.Now().UTC().Format(time.RFC3339),
			Timeout: timeout,
			List:    list,
		})
	}
}
