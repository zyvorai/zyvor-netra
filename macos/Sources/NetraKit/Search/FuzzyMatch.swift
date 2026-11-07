// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Subsequence fuzzy matcher (fzf-ish): rewards consecutive runs, word-start hits and prefixes.
public enum FuzzyMatch {
    public struct Result: Sendable, Equatable { public var score: Int; public var matched: [Int] }

    public static func match(query: String, in text: String) -> Result? {
        let q = Array(query.lowercased().filter { !$0.isWhitespace })
        let t = Array(text)
        let tl = Array(text.lowercased())
        if q.isEmpty { return Result(score: 0, matched: []) }
        guard tl.count == t.count, q.count <= t.count else { return nil }
        var matched: [Int] = []
        var score = 0, ti = 0, prev = -2
        for qc in q {
            var found = false
            while ti < tl.count {
                if tl[ti] == qc {
                    var s = 1
                    if ti == prev + 1 { s += 5 }
                    if ti == 0 { s += 8 }
                    else if !t[ti - 1].isLetter && !t[ti - 1].isNumber { s += 6 }
                    else if t[ti - 1].isLowercase && t[ti].isUppercase { s += 5 }
                    score += s; matched.append(ti); prev = ti; ti += 1; found = true
                    break
                }
                ti += 1
            }
            if !found { return nil }
        }
        score -= (matched.last! - matched.first!) - (q.count - 1)   // gap penalty
        if tl.starts(with: q) { score += 10 }
        if tl.count == q.count && tl == q { score += 20 }
        return Result(score: score, matched: matched)
    }

    /// Ranks items by best score across their keys; stable for ties, empty query keeps order.
    public static func rank<T>(_ items: [T], query: String, keys: (T) -> [String]) -> [(item: T, score: Int)] {
        let q = query.trimmingCharacters(in: .whitespaces)
        if q.isEmpty { return items.map { ($0, 0) } }
        var out: [(Int, Int, T)] = []
        for (i, it) in items.enumerated() {
            let best = keys(it).compactMap { match(query: q, in: $0)?.score }.max()
            if let b = best { out.append((b, i, it)) }
        }
        out.sort { $0.0 != $1.0 ? $0.0 > $1.0 : $0.1 < $1.1 }
        return out.map { ($0.2, $0.0) }
    }
}
