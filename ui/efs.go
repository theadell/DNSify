package ui

import "embed"

//go:embed templates/*
var TemplatesFS embed.FS

//go:embed static/*
var StatifFS embed.FS
