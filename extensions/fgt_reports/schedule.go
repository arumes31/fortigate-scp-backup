package fgt_reports

import (
	"errors"
	"time"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

// nextScheduledRun returns the next wall-clock occurrence strictly after the
// supplied time. Short months clamp the requested day to their final day. DST
// follows Go's IANA location rules; persistent occurrences prevent double runs.
func nextScheduledRun(s reportmodel.Schedule, after time.Time) (time.Time, error) {
	if s.Frequency == "on_backup" || s.Frequency == "" {
		return time.Time{}, nil
	}
	location, err := time.LoadLocation(s.Timezone)
	if err != nil {
		return time.Time{}, errors.New("invalid report schedule timezone")
	}
	if s.Hour < 0 || s.Hour > 23 || s.Minute < 0 || s.Minute > 59 || s.Weekday < 0 || s.Weekday > 6 || s.MonthDay < 1 || s.MonthDay > 31 {
		return time.Time{}, errors.New("invalid report schedule")
	}
	local := after.In(location)
	switch s.Frequency {
	case "daily", "weekly":
		for offset := 0; offset <= 8; offset++ {
			day := time.Date(local.Year(), local.Month(), local.Day()+offset, 12, 0, 0, 0, location)
			if s.Frequency == "weekly" && int(day.Weekday()) != s.Weekday {
				continue
			}
			candidate := time.Date(day.Year(), day.Month(), day.Day(), s.Hour, s.Minute, 0, 0, location)
			if candidate.After(after) {
				return candidate.UTC(), nil
			}
		}
	case "monthly":
		for offset := 0; offset <= 2; offset++ {
			month := time.Date(local.Year(), local.Month()+time.Month(offset), 1, 12, 0, 0, 0, location)
			last := time.Date(month.Year(), month.Month()+1, 0, 12, 0, 0, 0, location).Day()
			day := s.MonthDay
			if day > last {
				day = last
			}
			candidate := time.Date(month.Year(), month.Month(), day, s.Hour, s.Minute, 0, 0, location)
			if candidate.After(after) {
				return candidate.UTC(), nil
			}
		}
	default:
		return time.Time{}, errors.New("unsupported report schedule frequency")
	}
	return time.Time{}, errors.New("next report schedule could not be established")
}
