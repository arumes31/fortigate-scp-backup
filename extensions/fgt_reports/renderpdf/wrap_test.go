package renderpdf

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/signintech/gopdf"

	"github.com/arumes31/fortigate-scp-backup/internal/fortiosconfig"
	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

func TestWrapTextLayout(t *testing.T) {
	measure := func(text string) (float64, error) {
		width := 0.0
		for _, r := range text {
			if !unicode.Is(unicode.Mn, r) {
				width++
			}
		}
		return width, nil
	}
	for _, tc := range []struct {
		name, text string
		width      float64
		want       []string
	}{
		{"empty", "", 4, nil},
		{"word break", "hello world", 7, []string{"hello", "world"}},
		{"unbroken word", "abcdef", 2, []string{"ab", "cd", "ef"}},
		{"Unicode boundaries", "αβγδ", 2, []string{"αβ", "γδ"}},
		{"hard newlines", "ab\n\ncd\n", 10, []string{"ab", "", "cd"}},
		{"edge spaces", " ab cd ", 5, []string{" ab", "cd "}},
		{"repeated spaces", "ab  cd", 4, []string{"ab ", "cd"}},
		{"combining characters", "ab\u0300\u0300 cd", 3, []string{"ab\u0300\u0300", "cd"}},
		{"glyph wider than column", "abc", 0.5, []string{"a", "b", "c"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := wrapText(context.Background(), tc.text, tc.width, measure)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("wrap = %#v, %v; want %#v", got, err, tc.want)
			}
		})
	}
	for _, width := range []float64{0, -1} {
		if _, err := wrapText(context.Background(), "text", width, measure); err == nil {
			t.Fatal("invalid column width was accepted")
		}
	}
}

func TestWrapTextMatchesEmbeddedFontLayout(t *testing.T) {
	d := wrapTestDocument(t, context.Background())
	for _, text := range []string{
		"Configuration details and source evidence.",
		"Kundenportal-Übergabe: Größenänderung für Süd.",
		"  leading  and trailing spaces  ",
		"One line.\n\nAnother line.\n",
		strings.Repeat("LongUnbrokenObjectName", 6),
		"A\u0300 combining mark and ordinary words.",
	} {
		for _, bold := range []bool{false, true} {
			for _, size := range []float64{8.5, 13} {
				d.font(size, bold)
				for _, width := range []float64{60, 120, 250} {
					want, err := d.pdf.SplitTextWithWordWrap(text, width)
					if err != nil {
						t.Fatal(err)
					}
					got, err := wrapText(d.ctx, text, width, d.pdf.MeasureTextWidth)
					if err != nil || !reflect.DeepEqual(got, want) {
						t.Fatalf("bold=%v size=%g width=%g: wrap=%q, %v; want %q", bold, size, width, got, err, want)
					}
				}
			}
		}
	}
}

func TestWrapTextBoundsMeasurementWork(t *testing.T) {
	// Zero-width suffixes must not cause repeated measurement of growing
	// prefixes, even when visible text and spaces trigger further breaks.
	line := "a " + strings.Repeat("\u0300", 2048) + "b c"
	text := strings.Repeat(line+"\n", 32)
	measured := 0
	budget := 4 * utf8.RuneCountInString(text)
	measure := func(value string) (float64, error) {
		measured += utf8.RuneCountInString(value)
		if measured > budget {
			return 0, errors.New("text measurement exceeded linear work budget")
		}
		width := 0.0
		for _, r := range value {
			if r != '\u0300' {
				width++
			}
		}
		return width, nil
	}
	got, err := wrapText(context.Background(), text, 4, measure)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]string, 0, 64)
	for i := 0; i < 32; i++ {
		want = append(want, "a "+strings.Repeat("\u0300", 2048)+"b", "c")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("combining text was lost, duplicated, or wrapped incorrectly")
	}
}

func TestWrapTextCancellationDuringWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var measured []string
	measure := func(value string) (float64, error) {
		measured = append(measured, value)
		if value == "b" {
			cancel()
		}
		return 1, nil
	}
	got, err := wrapText(ctx, "ab"+strings.Repeat("c", 32000), 10, measure)
	if !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("cancellation must discard partial layout: %v, %v", got, err)
	}
	if strings.Contains(strings.Join(measured, ""), "c") {
		t.Fatal("measurement continued after cancellation")
	}
	failure := errors.New("font measurement failed")
	if _, err := wrapText(context.Background(), "a", 10, func(string) (float64, error) {
		return 0, failure
	}); !errors.Is(err, failure) {
		t.Fatalf("measurement error was lost: %v", err)
	}
}

type cancelDuringChecks struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (c *cancelDuringChecks) Err() error {
	c.remaining--
	if c.remaining == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestCleanCancellationDuringWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checks := &cancelDuringChecks{Context: ctx, cancel: cancel, remaining: 4}
	d := wrapTestDocument(t, checks)
	if text := d.clean(strings.Repeat("a\u0300", 32000)); text != "" || !errors.Is(d.err, context.Canceled) {
		t.Fatalf("cleaning must stop during work: returned bytes=%d error=%v", len(text), d.err)
	}
}

func TestRenderLongConfigurationEnums(t *testing.T) {
	const template = `#config-version=FG100F-7.4.7-FW-build2731-241205:opmode=0:vdom=0
config firewall vip
    edit edge
        set type "%s"
        set extip 203.0.113.1
        set mappedip 10.0.0.1
        set extintf wan1
        set portforward enable
        set protocol "%s"
        set extport 443
        set mappedport 443
    next
end
config firewall policy
    edit 1
        set srcintf wan1
        set dstintf any
        set srcaddr all
        set dstaddr edge
        set action "%s"
        set schedule always
        set service ALL
    next
end
`
	for _, field := range []string{"type", "protocol", "action"} {
		t.Run(field, func(t *testing.T) {
			values := map[string]string{"type": "static-nat", "protocol": "tcp", "action": "accept"}
			// A second combining rune and removed format characters cover a
			// different source representation reaching the same wrapping sink.
			payload := strings.Repeat("\u0300", 32000)
			if field != "type" {
				payload = strings.Repeat("\u0301\u200b", 32000)
			}
			values[field] = payload
			a, err := fortiosconfig.Analyze(context.Background(), []byte(fmt.Sprintf(template, values["type"], values["protocol"], values["action"])))
			if err != nil {
				t.Fatal(err)
			}
			if len(a.Exposures) != 1 {
				t.Fatalf("unexpected exposure count %d", len(a.Exposures))
			}
			ex := a.Exposures[0]
			carried := ex.Type
			switch field {
			case "protocol":
				carried = ex.External
			case "action":
				if len(ex.Trace) != 1 {
					t.Fatalf("unexpected trace count %d", len(ex.Trace))
				}
				carried = ex.Trace[0].Action
			}
			if !strings.Contains(carried, payload) {
				t.Fatal("fixture did not carry the long enum into the assessment")
			}
			p := reportmodel.DefaultProfile("en")
			p.Cover, p.Contents, p.Charts = false, false, nil
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			started := time.Now()
			_, err = RenderWithProfile(ctx, reportmodel.Source{FirewallID: 1}, a, "forwarding", p)
			elapsed := time.Since(started)
			if err != nil && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("unexpected rendering rejection: %v", err)
			}
			// This generous bound catches the former 22-second uninterruptible
			// call while tolerating slow/race-enabled CI hosts.
			if elapsed > 2*time.Second {
				t.Fatalf("rendering ignored its deadline for %s", elapsed)
			}
			t.Logf("%s enum: bytes=%d elapsed=%s error=%v", field, len(payload), elapsed, err)
		})
	}
}

func TestPDFMaximumLengthIntroduction(t *testing.T) {
	source, a := fixture()
	p := reportmodel.DefaultProfile("de")
	p.Intro = strings.Repeat("Übergabe ", 444) + "ENDE"
	if utf8.RuneCountInString(p.Intro) != 4000 {
		t.Fatal("fixture must exercise the permitted introduction length")
	}
	if _, err := RenderWithProfile(context.Background(), source, a, "technical", p); err != nil {
		t.Fatalf("maximum-length Unicode introduction was rejected: %v", err)
	}
}

func wrapTestDocument(t *testing.T, ctx context.Context) *document {
	t.Helper()
	pdf := &gopdf.GoPdf{}
	pdf.Start(gopdf.Config{PageSize: gopdf.Rect{W: pageWidth, H: pageHeight}})
	for _, font := range []struct{ family, path string }{{"sans", "fonts/DejaVuSans.ttf"}, {"bold", "fonts/DejaVuSans-Bold.ttf"}} {
		data, err := fontFiles.ReadFile(font.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := pdf.AddTTFFontData(font.family, data); err != nil {
			t.Fatal(err)
		}
	}
	return &document{pdf: pdf, ctx: ctx, glyphs: make(map[rune]bool)}
}
