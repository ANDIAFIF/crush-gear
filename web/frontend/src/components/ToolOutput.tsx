/**
 * Terminal-like tool output component
 */

import { useEffect, useRef } from 'react';

interface ToolOutputProps {
  lines: { line_num: number; line_text: string }[];
  autoScroll?: boolean;
}

export function ToolOutput({ lines, autoScroll = true }: ToolOutputProps) {
  const outputRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [lines, autoScroll]);

  return (
    <div ref={outputRef} className="terminal-output">
      {lines.length === 0 ? (
        <div className="text-gray-400 italic">No output yet...</div>
      ) : (
        lines.map((line) => (
          <div key={line.line_num} className="line font-mono">
            <span className="text-gray-500 mr-4">{line.line_num.toString().padStart(4, ' ')}</span>
            <span>{line.line_text}</span>
          </div>
        ))
      )}
    </div>
  );
}
