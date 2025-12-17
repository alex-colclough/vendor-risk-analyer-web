'use client';

import { useCallback, useEffect } from 'react';
import { Play, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useStore } from '@/store';
import { api } from '@/lib/api';
import { useAnalysisWebSocket } from '@/hooks/useWebSocket';
import { toast } from '@/hooks/use-toast';
import type { ProgressEvent } from '@/types';

export function AnalysisPanel() {
  const {
    sessionId,
    uploadedFiles,
    selectedFrameworks,
    analysisId,
    analysisStatus,
    progress,
    progressMessages,
    setAnalysisId,
    setAnalysisStatus,
    setProgress,
    addProgressMessage,
    clearProgressMessages,
    setResults,
  } = useStore();

  const handleWebSocketMessage = useCallback(
    (event: ProgressEvent) => {
      addProgressMessage(event);

      if (event.progress_percentage !== undefined) {
        setProgress(event.progress_percentage);
      }

      if (event.event_type === 'analysis_complete') {
        setAnalysisStatus('completed');
        toast({
          title: 'Analysis Complete',
          description: 'Your compliance analysis is ready',
        });

        // Fetch results using analysis_id from event data (avoids stale closure)
        const completedAnalysisId = (event.data?.analysis_id as string) || analysisId;
        if (completedAnalysisId) {
          api.getAnalysisResults(completedAnalysisId).then((response) => {
            if (response.data) {
              setResults(response.data as any);
            }
          });
        }
      } else if (event.event_type === 'analysis_error') {
        setAnalysisStatus('error');
        toast({
          title: 'Analysis Failed',
          description: event.message || 'An error occurred during analysis',
          variant: 'destructive',
        });
      }
    },
    [addProgressMessage, setProgress, setAnalysisStatus, setResults, analysisId]
  );

  const { connect, startAnalysis, isConnected } = useAnalysisWebSocket(
    sessionId,
    {
      onMessage: handleWebSocketMessage,
      onConnect: () => {
        console.log('WebSocket connected');
      },
    }
  );

  const handleStartAnalysis = async () => {
    if (uploadedFiles.length === 0) {
      toast({
        title: 'No files',
        description: 'Please upload at least one document',
        variant: 'destructive',
      });
      return;
    }

    if (selectedFrameworks.length === 0) {
      toast({
        title: 'No frameworks selected',
        description: 'Please select at least one compliance framework',
        variant: 'destructive',
      });
      return;
    }

    setAnalysisStatus('analyzing');
    setProgress(0);
    clearProgressMessages();

    // Start analysis via API
    const response = await api.startAnalysis(sessionId, selectedFrameworks);

    if (response.error) {
      setAnalysisStatus('error');
      toast({
        title: 'Failed to start analysis',
        description: response.error,
        variant: 'destructive',
      });
      return;
    }

    if (response.data) {
      setAnalysisId(response.data.analysis_id);

      // Connect WebSocket and start
      connect();

      // Wait for connection then start
      setTimeout(() => {
        startAnalysis(response.data!.analysis_id);
      }, 500);
    }
  };

  const canStart =
    uploadedFiles.length > 0 &&
    selectedFrameworks.length > 0 &&
    analysisStatus !== 'analyzing';

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span>Analysis</span>
          <Button
            onClick={handleStartAnalysis}
            disabled={!canStart}
            className="gap-2"
          >
            {analysisStatus === 'analyzing' ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Play className="h-4 w-4" />
                Start Analysis
              </>
            )}
          </Button>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {analysisStatus === 'analyzing' && (
          <>
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>Progress</span>
                <span>{Math.round(progress)}%</span>
              </div>
              <Progress value={progress} />
            </div>

            <ScrollArea className="h-48 rounded-md border p-4">
              <div className="space-y-2">
                {progressMessages.map((msg, i) => (
                  <div
                    key={i}
                    className="text-sm flex items-start gap-2 animate-slide-up"
                  >
                    <span className="text-muted-foreground text-xs whitespace-nowrap">
                      {new Date(msg.timestamp).toLocaleTimeString()}
                    </span>
                    <span
                      className={
                        msg.event_type.includes('error')
                          ? 'text-destructive'
                          : msg.event_type.includes('complete')
                          ? 'text-green-600 dark:text-green-400'
                          : ''
                      }
                    >
                      {msg.message}
                    </span>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </>
        )}

        {analysisStatus === 'idle' && (
          <p className="text-sm text-muted-foreground text-center py-8">
            Upload documents and select frameworks to begin analysis
          </p>
        )}

        {analysisStatus === 'completed' && (
          <p className="text-sm text-green-600 dark:text-green-400 text-center py-4">
            Analysis complete! View results below.
          </p>
        )}

        {analysisStatus === 'error' && (
          <p className="text-sm text-destructive text-center py-4">
            Analysis failed. Please try again.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
