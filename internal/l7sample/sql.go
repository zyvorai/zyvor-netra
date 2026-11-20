// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package l7sample

// sqlVerbs bounds the operation label for SQL protocols. The statement text is
// read only to find its first keyword and is never kept.
var sqlVerbs = set(
	"SELECT", "INSERT", "UPDATE", "DELETE", "BEGIN", "START", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE",
	"CREATE", "DROP", "ALTER", "TRUNCATE", "SET", "SHOW", "EXPLAIN", "COPY", "GRANT", "REVOKE", "VACUUM", "ANALYZE",
	"WITH", "CALL", "PREPARE", "EXECUTE", "DEALLOCATE", "LISTEN", "NOTIFY", "UNLISTEN", "LOCK", "MERGE", "REPLACE", "USE",
	"DECLARE", "FETCH", "CLOSE", "DISCARD", "RESET", "DESCRIBE", "DESC", "VALUES", "TABLE", "CHECKPOINT", "REINDEX", "CLUSTER", "COMMENT",
)

// sqlVerb finds the first keyword of a statement, skipping whitespace, a leading
// parenthesis and SQL comments, and returns it if it is an allowlisted verb.
func sqlVerb(b []byte) string {
	i := 0
	for i < len(b) {
		switch {
		case b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r' || b[i] == '(' || b[i] == ';':
			i++
		case i+1 < len(b) && b[i] == '-' && b[i+1] == '-':
			for i < len(b) && b[i] != '\n' {
				i++
			}
		case i+1 < len(b) && b[i] == '/' && b[i+1] == '*':
			end := -1
			for j := i + 2; j+1 < len(b); j++ {
				if b[j] == '*' && b[j+1] == '/' {
					end = j + 2
					break
				}
			}
			if end < 0 {
				return "OTHER"
			}
			i = end
		default:
			w, _ := upperWord(b[i:], 16)
			if w == "" {
				return "OTHER"
			}
			return pick(sqlVerbs, w)
		}
	}
	return "OTHER"
}
