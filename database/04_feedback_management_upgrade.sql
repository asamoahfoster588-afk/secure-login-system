BEGIN;

ALTER TABLE feedback
    ADD COLUMN IF NOT EXISTS subject VARCHAR(150);

UPDATE feedback
SET subject = 'Feedback'
WHERE subject IS NULL OR BTRIM(subject) = '';

ALTER TABLE feedback
    ALTER COLUMN subject SET NOT NULL;

ALTER TABLE feedback
    ADD COLUMN IF NOT EXISTS admin_response TEXT,
    ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;

COMMIT;
