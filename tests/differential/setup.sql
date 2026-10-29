DROP DATABASE IF EXISTS sqlguard_probe;
CREATE DATABASE sqlguard_probe DEFAULT CHARACTER SET utf8mb4;

CREATE TABLE sqlguard_probe.allowed_table (
  id INT,
  team VARCHAR(16),
  note TEXT
);
INSERT INTO sqlguard_probe.allowed_table VALUES
  (1, 'gold', 'a'),
  (2, 'silver', 'b'),
  (3, 'gold', 'c');

CREATE TABLE sqlguard_probe.forbidden_table (
  id INT,
  secret VARCHAR(32)
);
INSERT INTO sqlguard_probe.forbidden_table VALUES
  (1, 's1'),
  (2, 's2');

-- SELECT-only oracle account: a payload that tries to write must fail, and that
-- failure is itself a valid observation rather than an accident on real data.
DROP USER IF EXISTS 'sqlguard_oracle'@'%';
CREATE USER 'sqlguard_oracle'@'%' IDENTIFIED BY 'Oracle@12345';
GRANT SELECT ON sqlguard_probe.* TO 'sqlguard_oracle'@'%';
GRANT SELECT ON performance_schema.* TO 'sqlguard_oracle'@'%';
FLUSH PRIVILEGES;
