"""
Minimal RAG retriever for Version B.

A dependency-free TF-IDF retriever: it loads documents from a knowledge base,
splits them into chunks, builds a TF-IDF vector per chunk, and returns the
chunks most similar to a query by cosine similarity. This is the "chunk ->
embed -> vector store -> retrieve" pipeline in miniature.

TF-IDF (not neural embeddings) keeps the lab free and offline. Retrieval
quality doesn't matter for the attack: indirect injection depends on the
retriever pulling attacker-controlled text into the prompt at all, not on how
good the ranking is. Swap in an embedding backend later if you want.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

_WORD = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    return _WORD.findall(text.lower())


@dataclass
class Chunk:
    source: str  # filename the chunk came from
    text: str
    tf: Counter = None  # term frequencies, filled at index time


class Retriever:
    def __init__(self, chunk_words: int = 120) -> None:
        self.chunk_words = chunk_words
        self.chunks: list[Chunk] = []
        self.idf: dict[str, float] = {}

    def _split(self, text: str) -> list[str]:
        """Chunk on blank lines, then pack paragraphs up to chunk_words."""
        paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
        chunks, buf, count = [], [], 0
        for para in paras:
            n = len(para.split())
            if buf and count + n > self.chunk_words:
                chunks.append("\n\n".join(buf))
                buf, count = [], 0
            buf.append(para)
            count += n
        if buf:
            chunks.append("\n\n".join(buf))
        return chunks or [text.strip()]

    def add_dir(self, directory: Path) -> None:
        for path in sorted(directory.glob("*")):
            if path.is_file() and path.suffix in {".txt", ".md", ".csv"}:
                for text in self._split(path.read_text(encoding="utf-8")):
                    self.chunks.append(Chunk(source=path.name, text=text))

    def index(self) -> "Retriever":
        """Compute TF per chunk and IDF across the corpus."""
        df: Counter = Counter()
        for c in self.chunks:
            c.tf = Counter(tokenize(c.text))
            df.update(c.tf.keys())
        n = max(len(self.chunks), 1)
        self.idf = {t: math.log((1 + n) / (1 + d)) + 1 for t, d in df.items()}
        return self

    def _vec(self, tf: Counter) -> dict[str, float]:
        return {t: f * self.idf.get(t, 0.0) for t, f in tf.items()}

    @staticmethod
    def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
        if not a or not b:
            return 0.0
        common = set(a) & set(b)
        dot = sum(a[t] * b[t] for t in common)
        na = math.sqrt(sum(v * v for v in a.values()))
        nb = math.sqrt(sum(v * v for v in b.values()))
        return dot / (na * nb) if na and nb else 0.0

    def search(self, query: str, k: int = 3) -> list[tuple[Chunk, float]]:
        qv = self._vec(Counter(tokenize(query)))
        scored = [(c, self._cosine(qv, self._vec(c.tf))) for c in self.chunks]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [(c, s) for c, s in scored[:k] if s > 0]
