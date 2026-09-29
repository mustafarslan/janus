package compliance

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Pack is a framework's requirements, as data.
//
// The article text and the citation live here rather than in Go, because the
// people who should be reviewing them are not the people who review a build.
type Pack struct {
	// ID is stable and is what a report cites.
	ID           string `json:"id"`
	Framework    string `json:"framework"`
	Jurisdiction string `json:"jurisdiction"`
	// Version is the pack's own version, not the framework's. A pack is
	// versioned data: a legal review that changes a mapping produces a new
	// pack version, and a report says which one it was run against.
	Version  string    `json:"version"`
	Source   string    `json:"source"`
	Articles []Article `json:"articles"`
}

// Article is one requirement, and the checks that stand for it.
type Article struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Requires names checks from the vocabulary. An article that names none is
	// refused: an article nothing evaluates would report as satisfied, which is
	// the most expensive kind of green.
	Requires []string `json:"requires"`
	// Note says what the mapping does and does not claim. It is printed with
	// every finding, because "Art. 12 satisfied" without it invites a reader to
	// think more was checked than was.
	Note string `json:"note"`
}

// LoadPack reads and validates a pack.
func LoadPack(path string) (*Pack, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("compliance: reading pack: %w", err)
	}
	var pack Pack
	if err := json.Unmarshal(raw, &pack); err != nil {
		return nil, fmt.Errorf("compliance: parsing pack: %w", err)
	}
	if err := pack.Validate(); err != nil {
		return nil, err
	}
	return &pack, nil
}

// Validate refuses a pack that would report something it did not check.
func (p *Pack) Validate() error {
	switch {
	case p.ID == "":
		return fmt.Errorf("compliance: a pack needs an id, because a report cites it")
	case p.Version == "":
		return fmt.Errorf("compliance: pack %q needs a version; a report has to say which "+
			"mapping it was run against, and 'the current one' is not an answer six "+
			"months later", p.ID)
	case len(p.Articles) == 0:
		return fmt.Errorf("compliance: pack %q has no articles", p.ID)
	}
	for _, article := range p.Articles {
		if article.ID == "" {
			return fmt.Errorf("compliance: pack %q has an article with no id", p.ID)
		}
		if len(article.Requires) == 0 {
			return fmt.Errorf("compliance: pack %q article %q names no checks. An article "+
				"nothing evaluates reports as satisfied, which is worse than an article "+
				"nobody mapped", p.ID, article.ID)
		}
		for _, name := range article.Requires {
			if _, ok := checks[name]; !ok {
				return fmt.Errorf("compliance: pack %q article %q requires %q, which is not "+
					"a check this build knows. Known checks: %s",
					p.ID, article.ID, name, strings.Join(CheckNames(), ", "))
			}
		}
	}
	return nil
}

// LoadPacks reads every pack in a directory.
func LoadPacks(dir string) ([]*Pack, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("compliance: reading pack directory: %w", err)
	}
	var packs []*Pack
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		pack, err := LoadPack(dir + "/" + entry.Name())
		if err != nil {
			return nil, err
		}
		packs = append(packs, pack)
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].ID < packs[j].ID })
	if len(packs) == 0 {
		return nil, fmt.Errorf("compliance: no packs in %s", dir)
	}
	return packs, nil
}
