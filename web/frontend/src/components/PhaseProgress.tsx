/**
 * Phase progress timeline component
 */

interface PhaseProgressProps {
  phases: {
    number: number;
    name: string;
    status: 'pending' | 'running' | 'completed' | 'error';
  }[];
}

export function PhaseProgress({ phases }: PhaseProgressProps) {
  return (
    <div className="w-full py-6">
      <div className="flex items-center justify-between">
        {phases.map((phase, index) => (
          <div key={phase.number} className="flex-1 flex items-center">
            <div className="flex flex-col items-center flex-1">
              <div
                className={`
                  w-12 h-12 rounded-full flex items-center justify-center font-bold text-lg
                  ${phase.status === 'completed' && 'bg-green-500 text-white'}
                  ${phase.status === 'running' && 'bg-blue-500 text-white animate-pulse'}
                  ${phase.status === 'error' && 'bg-red-500 text-white'}
                  ${phase.status === 'pending' && 'bg-gray-300 text-gray-600'}
                `}
              >
                {phase.number}
              </div>
              <div className="mt-2 text-center">
                <div className="text-sm font-semibold">{phase.name}</div>
                <div className="text-xs text-gray-500 capitalize">{phase.status}</div>
              </div>
            </div>
            {index < phases.length - 1 && (
              <div
                className={`
                  flex-1 h-1 mx-4
                  ${phase.status === 'completed' ? 'bg-green-500' : 'bg-gray-300'}
                `}
              />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
