package main

import (
	"fmt"
	"github.com/bitly/go-simplejson"
	"io/ioutil"
	"strings"
)

func genComposer(pkg, sdk string) {
	spts := strings.Split(pkg, ".")

	json := simplejson.New()

	json.Set("name", fmt.Sprintf("%s/%s", spts[0], strings.Join(spts[1:], "-")))

	titles := make([]string, 0)
	for _, part := range spts {
		titles = append(titles, strings.Title(part))
	}

	json.SetPath([]string{"autoload", "psr-4", strings.Join(titles, "\\") + "\\"}, strings.Join(titles, "/"))

	bytes, err := json.EncodePretty()
	if err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(fmt.Sprintf("%s/composer.json", sdk), bytes, 0644); err != nil {
		panic(err)
	}
}
