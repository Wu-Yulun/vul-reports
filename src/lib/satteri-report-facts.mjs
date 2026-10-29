/**
 * Rebuilds the fact block that opens every report section as a two-column
 * table.
 *
 * A section is introduced by an `h2` and then the same few labelled lines,
 * for example:
 *
 *     Brief description: An attacker uploads ...
 *     Affected versions: 0.1.13 to 2.9.0
 *     Preconditions: ...
 *     Fix: [edgeever commit dc5a55a1](https://github.com/...)
 *
 * Markdown turns each line into its own paragraph, which reads as a run of
 * unconnected sentences. The labels are a small, known set in both report
 * languages, so the block can be recognised in the syntax tree and rebuilt as
 * a table: the label, colon included, becomes the row header and the rest of
 * the line the cell.
 * The line is split after parsing, so links, inline code and emphasis inside a
 * value keep the children Markdown already gave them.
 *
 * Only a contiguous block directly after an `h2` is converted, and only when
 * at least two known labels are present. Prose that merely starts with a word
 * such as "Fix:" therefore stays a paragraph, and so does a report that never
 * adopted the convention.
 *
 * The processor in use is Sätteri, so this is a HAST plugin: the `after` hook
 * sees the finished tree and queues the structural edits for its final pass.
 */

/** Labels that open a fact line, in both report languages. */
const LABELS = new Set([
  'Brief description',
  'Affected versions',
  'Preconditions',
  'Fix',
  '简要描述',
  '影响版本',
  '前置条件',
  '修复',
]);

/**
 * Splits `Label: value` at the first colon (half or full width). The label is
 * excluded from the character class, so a colon inside the value never wins.
 * The colon is captured as written, so the row header keeps it, in the same
 * width the author used.
 */
const LABELLED = /^([^:：]{1,40}?)\s*([:：])[ \t]*/;

const isBlank = (node) => node.type === 'text' && node.value.trim() === '';

const element = (tagName, children, properties = {}) => ({
  type: 'element',
  tagName,
  properties,
  children,
});

/**
 * Turns one paragraph into `{ label, value }`, where `value` holds the
 * paragraph's children with the `Label:` prefix removed from the leading text
 * node. Returns `null` when the paragraph does not start with a known label.
 */
function readFact(node) {
  if (node.type !== 'element' || node.tagName !== 'p') return null;

  const [first] = node.children;
  if (!first || first.type !== 'text') return null;

  const match = first.value.match(LABELLED);
  if (!match) return null;

  const label = `${match[1].trim()}${match[2]}`;
  if (!LABELS.has(match[1].trim())) return null;

  const rest = first.value.slice(match[0].length);
  const value = [...(rest ? [{ type: 'text', value: rest }] : []), ...node.children.slice(1)];

  return { label, value };
}

function factTable(facts) {
  return element(
    'table',
    [
      element(
        'tbody',
        facts.map((fact) =>
          element('tr', [
            element('th', [{ type: 'text', value: fact.label }], { scope: 'row' }),
            element('td', fact.value),
          ]),
        ),
      ),
    ],
    { className: ['report-facts'] },
  );
}

export default {
  name: 'report-facts',
  after(root, ctx) {
    const children = root.children;

    for (let index = 0; index < children.length; index++) {
      const heading = children[index];
      if (heading.type !== 'element' || heading.tagName !== 'h2') continue;

      // The block starts with the first non-blank sibling after the heading.
      let start = index + 1;
      while (start < children.length && isBlank(children[start])) start++;

      // Collect the contiguous run of fact lines. Blank text nodes between
      // block elements are skipped; anything else ends the block.
      const facts = [];
      let end = start;
      while (end < children.length) {
        const child = children[end];
        if (isBlank(child)) {
          end++;
          continue;
        }

        const fact = readFact(child);
        if (!fact) break;

        facts.push(fact);
        end++;
      }

      if (facts.length < 2) continue;

      // The labels are now cells: drop the paragraphs that carried them and
      // swap the first one for the table.
      for (let drop = start + 1; drop < end; drop++) {
        if (!isBlank(children[drop])) ctx.removeNode(children[drop]);
      }
      ctx.replaceNode(children[start], factTable(facts));
    }
  },
};
