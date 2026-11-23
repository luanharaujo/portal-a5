-- Scheduled tab check (watchTabs): one warning per (tab, code, since), looked up by label.
CREATE INDEX IF NOT EXISTS device_alerts_kind_label ON device_alerts (kind, label);
