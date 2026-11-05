-- Group names are stored in English; the page shows them through public/locale.
-- Group names cannot be edited from the page, so overwriting them is safe.
UPDATE groups SET name = 'Owner' WHERE id = 'owner';
UPDATE groups SET name = 'Residents' WHERE id = 'residents';
