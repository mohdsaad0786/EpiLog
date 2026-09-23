package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mohdsaad0786/EpiLog/internal/story"
	_ "modernc.org/sqlite"
)

type StoryStore interface {
	Save(story.Story) error
	List(context.Context, string, string, string, int) ([]story.Story, error)
	Get(context.Context, string) (story.Story, error)
	MarkFalsePositive(context.Context, string) error
	Prune(context.Context, time.Time) error
	SaveBlock(string, time.Time, string) error
	ActiveBlocks(context.Context, time.Time) (map[string]time.Time, error)
	Close() error
}
type SQLite struct{ db *sql.DB }

func Open(path string) (*SQLite, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS stories (id TEXT PRIMARY KEY, attacker_ip TEXT NOT NULL, last_seen TEXT NOT NULL, verdict TEXT NOT NULL, threat_score INTEGER NOT NULL, content TEXT NOT NULL, false_positive INTEGER NOT NULL DEFAULT 0); CREATE INDEX IF NOT EXISTS stories_last_seen ON stories(last_seen DESC); CREATE INDEX IF NOT EXISTS stories_ip ON stories(attacker_ip); CREATE INDEX IF NOT EXISTS stories_verdict ON stories(verdict); CREATE TABLE IF NOT EXISTS vault_blocks (ip TEXT PRIMARY KEY, until TEXT NOT NULL, reason TEXT NOT NULL);`); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLite{db: db}, nil
}
func (store *SQLite) Save(item story.Story) error {
	raw, err := json.Marshal(item)
	if err != nil {
		return err
	}
	_, err = store.db.Exec(`INSERT INTO stories(id,attacker_ip,last_seen,verdict,threat_score,content) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,verdict=excluded.verdict,threat_score=excluded.threat_score,content=excluded.content`, item.ID, item.AttackerIP, item.LastSeen.UTC().Format(time.RFC3339Nano), item.Verdict, item.ThreatScore, string(raw))
	return err
}
func (store *SQLite) List(ctx context.Context, ip, verdict, since string, limit int) ([]story.Story, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := store.db.QueryContext(ctx, `SELECT content,false_positive FROM stories WHERE (?='' OR attacker_ip=?) AND (?='' OR verdict=?) AND (?='' OR last_seen>=?) ORDER BY last_seen DESC LIMIT ?`, ip, ip, verdict, verdict, since, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]story.Story, 0)
	for rows.Next() {
		var raw string
		var falsePositive bool
		if err := rows.Scan(&raw, &falsePositive); err != nil {
			return nil, err
		}
		var item story.Story
		if err := json.Unmarshal([]byte(raw), &item); err != nil {
			return nil, err
		}
		item.FalsePositive = falsePositive
		items = append(items, item)
	}
	return items, rows.Err()
}
func (store *SQLite) Get(ctx context.Context, id string) (story.Story, error) {
	var raw string
	var falsePositive bool
	err := store.db.QueryRowContext(ctx, `SELECT content,false_positive FROM stories WHERE id=?`, id).Scan(&raw, &falsePositive)
	if err != nil {
		return story.Story{}, err
	}
	var item story.Story
	err = json.Unmarshal([]byte(raw), &item)
	item.FalsePositive = falsePositive
	return item, err
}
func (store *SQLite) MarkFalsePositive(ctx context.Context, id string) error {
	result, err := store.db.ExecContext(ctx, `UPDATE stories SET false_positive=1 WHERE id=?`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("story not found: %s", id)
	}
	return nil
}
func (store *SQLite) Prune(ctx context.Context, before time.Time) error {
	_, err := store.db.ExecContext(ctx, `DELETE FROM stories WHERE last_seen < ?`, before.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	_, err = store.db.ExecContext(ctx, `DELETE FROM vault_blocks WHERE until < ?`, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
func (store *SQLite) Close() error { return store.db.Close() }
func (store *SQLite) SaveBlock(ip string, until time.Time, reason string) error {
	_, err := store.db.Exec(`INSERT INTO vault_blocks(ip,until,reason) VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE SET until=excluded.until,reason=excluded.reason`, ip, until.UTC().Format(time.RFC3339Nano), reason)
	return err
}
func (store *SQLite) ActiveBlocks(ctx context.Context, now time.Time) (map[string]time.Time, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT ip,until FROM vault_blocks WHERE until>?`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]time.Time)
	for rows.Next() {
		var ip, until string
		if err := rows.Scan(&ip, &until); err != nil {
			return nil, err
		}
		deadline, err := time.Parse(time.RFC3339Nano, until)
		if err != nil {
			return nil, err
		}
		result[ip] = deadline
	}
	return result, rows.Err()
}
