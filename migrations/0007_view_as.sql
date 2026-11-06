-- "See as a resident": an admin browser session can show itself as one non-admin group.
-- The group id lives on the session (one device only); the portal checks it on every request
-- and ignores it unless the person is still an admin and the group is still not an admin group.
ALTER TABLE sessions ADD COLUMN view_as TEXT;
