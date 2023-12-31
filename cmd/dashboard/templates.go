package main

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/theadell/dnsify/internal/auth"
	"github.com/theadell/dnsify/internal/dnsservice"
)

func loadTemplates(tmplFS embed.FS) map[string]*template.Template {
	cache := make(map[string]*template.Template)

	baseTemplateContent, err := tmplFS.ReadFile("templates/base.gotmpl")
	if err != nil {
		log.Fatal(err)
	}
	baseTemplate, err := template.New("base.gohtmltmpl").Parse(string(baseTemplateContent))
	if err != nil {
		log.Fatal(err)
	}

	fragments, err := tmplFS.ReadDir("templates/fragments")
	if err != nil {
		log.Fatal(err)
	}
	for _, fragment := range fragments {
		fragmentName := stripExtension(fragment.Name())
		fragmentContent, err := tmplFS.ReadFile("templates/fragments/" + fragment.Name())
		if err != nil {
			log.Fatal(err)
		}
		fragmentTemplate, err := template.New(fragmentName).Parse(string(fragmentContent))
		if err != nil {
			log.Fatal(err)
		}
		cache[fragmentName] = fragmentTemplate

		_, err = baseTemplate.New(fragmentName).Parse(string(fragmentContent))
		if err != nil {
			log.Fatal(err)
		}
	}

	partials, err := tmplFS.ReadDir("templates/partials")
	if err != nil {
		log.Fatal(err)
	}

	for _, partial := range partials {
		partialName := stripExtension(partial.Name())
		partialContent, err := tmplFS.ReadFile("templates/partials/" + partial.Name())
		if err != nil {
			log.Fatal(err)
		}
		_, err = baseTemplate.New(partialName).Parse(string(partialContent))
		if err != nil {
			log.Fatal(err)
		}

	}

	pages, err := tmplFS.ReadDir("templates/pages")
	if err != nil {
		log.Fatal(err)
	}
	for _, page := range pages {
		tmpl := template.Must(baseTemplate.Clone())
		pageName := stripExtension(page.Name())
		pageContent, err := tmplFS.ReadFile("templates/pages/" + page.Name())
		if err != nil {
			log.Fatal(err)
		}
		_, err = tmpl.New(pageName).Parse(string(pageContent))
		if err != nil {
			log.Fatal(err)
		}
		cache[pageName] = tmpl
	}

	return cache
}
func stripExtension(filename string) string {
	return strings.TrimSuffix(filename, filepath.Ext(filename))
}

func (app *App) render(w http.ResponseWriter, status int, page string, data any) {
	ts, ok := app.templateCache[page]
	if !ok {
		err := fmt.Errorf("the template %s does not exist", page)
		app.serverError(w, err)
		return
	}

	buf := new(bytes.Buffer)

	if err := ts.Execute(buf, data); err != nil {
		app.serverError(w, err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	buf.WriteTo(w)
}

func (app *App) renderTemplateFragment(w http.ResponseWriter, status int, page string, fragment string, data any) {
	ts, ok := app.templateCache[page]
	if !ok {
		err := fmt.Errorf("the template %s does not exist", page)
		app.serverError(w, err)
		return
	}

	buf := new(bytes.Buffer)

	if err := ts.ExecuteTemplate(buf, fragment, data); err != nil {
		app.serverError(w, err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

func ConstructSSEMessage(tmpl *template.Template, data any, eventName string, counter int) ([]byte, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("Failed to execute template: %v", err)
	}

	lines := strings.Split(buf.String(), "\n")
	message := fmt.Sprintf("id: %d\nevent: %s\n", counter, eventName)
	for _, line := range lines {
		message += fmt.Sprintf("data: %s\n", line)
	}
	message += "\n"

	return []byte(message), nil
}

type DashboardPageData struct {
	Zone    string
	Records []dnsservice.Record
}

type LoginTemplateData struct {
	auth.LoginPromptData
	ErrorMessage string
}
