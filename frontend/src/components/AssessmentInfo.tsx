'use client';

import { Building2, User, Ticket } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useStore } from '@/store';

/**
 * Sanitize user input to prevent XSS and injection attacks.
 * This provides client-side validation in addition to server-side sanitization.
 */
function sanitizeInput(value: string, maxLength: number = 100): string {
  return value
    .replace(/[<>]/g, '') // Remove angle brackets (basic XSS prevention)
    .replace(/[\x00-\x1F\x7F]/g, '') // Remove control characters
    .trim()
    .substring(0, maxLength);
}

export function AssessmentInfo() {
  const {
    vendorName,
    reviewedBy,
    ticketNumber,
    setVendorName,
    setReviewedBy,
    setTicketNumber,
  } = useStore();

  const handleVendorNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setVendorName(sanitizeInput(e.target.value, 100));
  };

  const handleReviewedByChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setReviewedBy(sanitizeInput(e.target.value, 100));
  };

  const handleTicketNumberChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setTicketNumber(sanitizeInput(e.target.value, 50));
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Building2 className="h-5 w-5" />
          Assessment Information
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="vendor-name" className="flex items-center gap-2">
            <Building2 className="h-4 w-4 text-muted-foreground" />
            Vendor Name
          </Label>
          <Input
            id="vendor-name"
            placeholder="Enter vendor name (e.g., Acme Corp)"
            value={vendorName}
            onChange={handleVendorNameChange}
            maxLength={100}
            pattern="[A-Za-z0-9\s\-\.\,\&]+"
          />
          <p className="text-xs text-muted-foreground">
            Used in the report title and exported filename
          </p>
        </div>

        <div className="space-y-2">
          <Label htmlFor="reviewed-by" className="flex items-center gap-2">
            <User className="h-4 w-4 text-muted-foreground" />
            Reviewed By
          </Label>
          <Input
            id="reviewed-by"
            placeholder="Enter analyst name"
            value={reviewedBy}
            onChange={handleReviewedByChange}
            maxLength={100}
            pattern="[A-Za-z0-9\s\-\.\,]+"
          />
          <p className="text-xs text-muted-foreground">
            Name of the analyst performing the review
          </p>
        </div>

        <div className="space-y-2">
          <Label htmlFor="ticket-number" className="flex items-center gap-2">
            <Ticket className="h-4 w-4 text-muted-foreground" />
            Ticket/Request Number
          </Label>
          <Input
            id="ticket-number"
            placeholder="Enter ticket or request number"
            value={ticketNumber}
            onChange={handleTicketNumberChange}
            maxLength={50}
            pattern="[A-Za-z0-9\-\_]+"
          />
          <p className="text-xs text-muted-foreground">
            Reference number for tracking (e.g., JIRA-1234)
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
