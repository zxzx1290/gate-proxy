package main

import (
	"fmt"
	"os"
	"strings"
)

type View struct {
	template string
}

func NewView(templatePath string) (*View, error) {
	data, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("讀取模板失敗: %w", err)
	}
	return &View{template: string(data)}, nil
}

func (v *View) Render(host, ip, pathname string, count int, loginURL string) string {
	r := strings.NewReplacer(
		"<?= host ?>", host,
		"<?= ip ?>", ip,
		"<?= pathname ?>", pathname,
		"<?= count ?>", fmt.Sprintf("%d", count),
		"<?= loginurl ?>", loginURL,
	)
	return r.Replace(v.template)
}
