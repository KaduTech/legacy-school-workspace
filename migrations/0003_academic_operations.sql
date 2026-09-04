-- Imported from the school-supplied 2026–2027 academic calendar. Dates are
-- inclusive and intentionally remain separate from live class events so that
-- a closure cannot accidentally be treated as a scheduled lesson.
CREATE TABLE IF NOT EXISTS academic_dates (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  starts_on TEXT NOT NULL,
  ends_on TEXT NOT NULL,
  category TEXT NOT NULL CHECK(category IN ('term','closure','holiday','exam','program','event','reporting')),
  is_no_class INTEGER NOT NULL DEFAULT 0 CHECK(is_no_class IN (0,1)),
  source TEXT NOT NULL DEFAULT 'academic_calendar_2026_2027',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(title, starts_on, ends_on)
);

-- A replacement for the informal Telegram escalation trail. It captures a
-- report without automatically contacting a parent or marking an unenrolled
-- learner absent; those decisions stay with authorized school staff.
CREATE TABLE IF NOT EXISTS operational_incidents (
  id TEXT PRIMARY KEY,
  reporter_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  group_id TEXT REFERENCES groups(id) ON DELETE SET NULL,
  kind TEXT NOT NULL CHECK(kind IN ('teacher_absence','class_no_show','link_failure','student_placement','other')),
  learning_mode TEXT NOT NULL DEFAULT 'unknown' CHECK(learning_mode IN ('group','one_to_one','club','unknown')),
  occurred_at TEXT NOT NULL,
  waited_minutes INTEGER CHECK(waited_minutes IS NULL OR waited_minutes >= 0),
  details TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','escalated','resolved')),
  lss_notified_at TEXT,
  resolution TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_academic_dates_range ON academic_dates(starts_on, ends_on);
CREATE INDEX IF NOT EXISTS idx_incidents_status_occurred ON operational_incidents(status, occurred_at);

INSERT OR IGNORE INTO academic_dates (id,title,starts_on,ends_on,category,is_no_class) VALUES
  ('acad-2026-08-14-parent-meeting','New School Year Parent Meeting','2026-08-14','2026-08-14','event',0),
  ('acad-2026-08-17-first-day','First Day of Classes','2026-08-17','2026-08-17','term',0),
  ('acad-2026-09-07-labor-day','Labor Day','2026-09-07','2026-09-07','holiday',1),
  ('acad-2026-09-08-clubs-begin','Virtual Clubs Begin','2026-09-08','2026-09-08','program',0),
  ('acad-2026-09-11-ta-fall','Teacher Assistant Program: Fall registration opens','2026-09-11','2026-09-11','program',0),
  ('acad-2026-10-16-peer-fall','Peer Mentorship Program: Fall registration opens','2026-10-16','2026-10-16','program',0),
  ('acad-2026-10-23-es-trip','Elementary School Virtual Field Trip','2026-10-23','2026-10-23','event',0),
  ('acad-2026-11-02-career-month','Career Month','2026-11-02','2026-11-27','program',0),
  ('acad-2026-11-11-veterans-day','Veterans Day','2026-11-11','2026-11-11','holiday',1),
  ('acad-2026-11-23-thanksgiving','Thanksgiving Break','2026-11-23','2026-11-29','closure',1),
  ('acad-2026-12-07-exams','First-semester Exam Period','2026-12-07','2026-12-11','exam',0),
  ('acad-2026-12-14-retakes','First-semester Exam Retake Period','2026-12-14','2026-12-18','exam',0),
  ('acad-2026-12-21-christmas-break','Christmas Break','2026-12-21','2027-01-03','closure',1),
  ('acad-2026-12-25-christmas','Christmas Day','2026-12-25','2026-12-25','holiday',1),
  ('acad-2026-12-31-report-cards','Fall Semester Report Cards','2026-12-31','2026-12-31','reporting',0),
  ('acad-2027-01-04-classes-resume','Classes Resume','2027-01-04','2027-01-04','term',0),
  ('acad-2027-01-11-clubs-resume','Virtual Clubs Resume','2027-01-11','2027-01-11','program',0),
  ('acad-2027-01-15-ta-spring','Teacher Assistant Program: Spring registration opens','2027-01-15','2027-01-15','program',0),
  ('acad-2027-01-18-mlk','Martin Luther King Jr. Day','2027-01-18','2027-01-18','holiday',1),
  ('acad-2027-02-15-presidents','Presidents’ Day','2027-02-15','2027-02-15','holiday',1),
  ('acad-2027-02-26-ms-trip','Middle School Virtual Field Trip','2027-02-26','2027-02-26','event',0),
  ('acad-2027-03-12-peer-spring','Peer Mentorship Program: Spring registration opens','2027-03-12','2027-03-12','program',0),
  ('acad-2027-03-22-spring-break','Spring Break','2027-03-22','2027-03-26','closure',1),
  ('acad-2027-04-19-patriots','Patriots’ Day','2027-04-19','2027-04-19','holiday',1),
  ('acad-2027-04-30-hs-trip','High School Virtual Field Trip','2027-04-30','2027-04-30','event',0),
  ('acad-2027-05-10-exams','Second-semester Exam Period','2027-05-10','2027-05-14','exam',0),
  ('acad-2027-05-14-clubs-end','Last Day of Virtual Clubs','2027-05-14','2027-05-14','program',0),
  ('acad-2027-05-17-retakes','Second-semester Exam Retake Period','2027-05-17','2027-05-21','exam',0),
  ('acad-2027-05-21-last-day','Last Day of Classes','2027-05-21','2027-05-21','term',0),
  ('acad-2027-05-31-memorial','Memorial Day','2027-05-31','2027-05-31','holiday',1),
  ('acad-2027-05-31-report-cards','Spring Semester Report Cards','2027-05-31','2027-05-31','reporting',0),
  ('acad-2027-06-01-summer-break','Summer Break','2027-06-01','2027-06-15','closure',1),
  ('acad-2027-06-04-graduation','Graduation','2027-06-04','2027-06-04','event',0),
  ('acad-2027-06-07-summer-school','Summer School','2027-06-07','2027-06-30','term',0);
