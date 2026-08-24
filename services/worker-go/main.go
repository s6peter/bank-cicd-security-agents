package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

func main() {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://voting:voting@localhost:5432/voting?sslmode=disable"
	}

	pollSeconds, err := strconv.Atoi(os.Getenv("POLL_SECONDS"))
	if err != nil || pollSeconds < 1 {
		pollSeconds = 15
	}

	for {
		if err := printResults(databaseURL); err != nil {
			log.Printf("worker error: %v", err)
		}
		time.Sleep(time.Duration(pollSeconds) * time.Second)
	}
}

func printResults(databaseURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	rows, err := conn.Query(ctx, `
		SELECT season, COUNT(*)::int
		FROM votes
		GROUP BY season
		ORDER BY season
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	counts := map[string]int{"spring": 0, "summer": 0, "fall": 0, "winter": 0}
	for rows.Next() {
		var season string
		var count int
		if err := rows.Scan(&season, &count); err != nil {
			return err
		}
		counts[season] = count
	}
	if err := rows.Err(); err != nil {
		return err
	}

	fmt.Printf("season vote totals: spring=%d summer=%d fall=%d winter=%d\n",
		counts["spring"], counts["summer"], counts["fall"], counts["winter"])
	return nil
}
