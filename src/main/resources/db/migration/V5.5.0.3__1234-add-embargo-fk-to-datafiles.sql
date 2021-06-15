ALTER TABLE datafile ADD COLUMN IF NOT EXISTS embargo_id BIGINT;

ALTER TABLE datafile ADD CONSTRAINT fk_datafiles_embargo_id foreign key (embargo_id) REFERENCES embargo(id);
