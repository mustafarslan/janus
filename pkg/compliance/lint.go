package compliance

import (
	"fmt"
	"sort"
	"strings"
)

// Finding is one article's outcome.
type Finding struct {
	PackID    string `json:"pack_id"`
	ArticleID string `json:"article_id"`
	Title     string `json:"title"`
	Note      string `json:"note,omitempty"`
	// Status is "satisfied", "exposed" or "unknown".
	//
	// Unknown is not a milder kind of satisfied. It means a check could not run
	// — no policy was supplied, or there was nothing of that kind to look at —
	// and reporting it as a pass is how a report comes to claim more than
	// anybody established.
	Status string   `json:"status"`
	Detail []string `json:"detail"`
}

// Report is a lint run.
type Report struct {
	Findings  []Finding `json:"findings"`
	Satisfied int       `json:"satisfied"`
	Exposed   int       `json:"exposed"`
	Unknown   int       `json:"unknown"`
}

// Statuses a finding can carry.
const (
	StatusSatisfied = "satisfied"
	StatusExposed   = "exposed"
	StatusUnknown   = "unknown"
)

// Lint evaluates packs against what a deployment has declared.
//
// It reads declarations and rules, not a log: an article about controls asks
// what is allowed to happen, and a log answers what did. Running before an audit
// is the point — a finding somebody can act on in a sprint is worth more than
// the same finding in an inspector's report.
func Lint(subject Subject, packs []*Pack) *Report {
	report := &Report{}
	for _, pack := range packs {
		for _, article := range pack.Articles {
			finding := Finding{
				PackID: pack.ID, ArticleID: article.ID,
				Title: article.Title, Note: article.Note,
				Status: StatusSatisfied,
			}
			for _, name := range article.Requires {
				result := checks[name](subject)
				finding.Detail = append(finding.Detail, name+": "+result.Detail)
				switch {
				case !result.Satisfied && !result.Unknown:
					// One failing check exposes the article. It cannot be
					// outvoted by the others: an article is a requirement, not
					// a score.
					finding.Status = StatusExposed
				case result.Unknown && finding.Status == StatusSatisfied:
					finding.Status = StatusUnknown
				}
			}
			switch finding.Status {
			case StatusSatisfied:
				report.Satisfied++
			case StatusExposed:
				report.Exposed++
			default:
				report.Unknown++
			}
			report.Findings = append(report.Findings, finding)
		}
	}
	sort.SliceStable(report.Findings, func(i, j int) bool {
		if report.Findings[i].PackID != report.Findings[j].PackID {
			return report.Findings[i].PackID < report.Findings[j].PackID
		}
		return report.Findings[i].ArticleID < report.Findings[j].ArticleID
	})
	return report
}

// Clean reports whether anything is exposed.
//
// Unknown does not count as clean and does not count as exposed. It is a
// question somebody has to answer, and collapsing it into either would lose the
// distinction that makes the report worth reading.
func (r *Report) Clean() bool { return r.Exposed == 0 }

func (r *Report) String() string {
	var b strings.Builder
	current := ""
	for _, f := range r.Findings {
		if f.PackID != current {
			fmt.Fprintf(&b, "\n%s\n", f.PackID)
			current = f.PackID
		}
		mark := map[string]string{
			StatusSatisfied: "ok     ", StatusExposed: "EXPOSED", StatusUnknown: "unknown",
		}[f.Status]
		fmt.Fprintf(&b, "  %s %s — %s\n", mark, f.ArticleID, f.Title)
		for _, detail := range f.Detail {
			fmt.Fprintf(&b, "          %s\n", detail)
		}
		if f.Note != "" {
			fmt.Fprintf(&b, "          note: %s\n", f.Note)
		}
	}
	fmt.Fprintf(&b, "\n%d satisfied, %d exposed, %d unknown\n",
		r.Satisfied, r.Exposed, r.Unknown)
	if r.Unknown > 0 {
		fmt.Fprintf(&b, "an unknown is a question nobody has answered, not a mild pass\n")
	}
	return b.String()
}
