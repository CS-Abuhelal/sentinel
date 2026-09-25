type Props = { ids: string[]; refs: Map<string, string> };

export function Cites({ ids, refs }: Props) {
  if (ids.length === 0) return null;
  return (
    <span className="cites" aria-label="Cited evidence">
      {ids.map((id) => {
        const ref = refs.get(id) ?? "?";
        return (
          <a key={id} className="tag tag--link" href={`#evidence-${ref}`}>
            {ref}
          </a>
        );
      })}
    </span>
  );
}
