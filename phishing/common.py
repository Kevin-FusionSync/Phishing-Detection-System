from dataclasses import dataclass, asdict


@dataclass
class Finding:
    name: str
    category: str
    weight: float
    detail: str

    def to_dict(self):
        return asdict(self)


def noisy_or(weights):
    remaining = 1.0
    for w in weights:
        remaining *= 1.0 - max(0.0, min(float(w), 1.0))
    return 1.0 - remaining
