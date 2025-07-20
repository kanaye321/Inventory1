import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Link } from "wouter";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { PlusIcon, CheckCircleIcon, MonitorIcon, CalendarIcon, DownloadIcon } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import ITEquipmentForm from "@/components/it-equipment/it-equipment-form";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { Separator } from "@/components/ui/separator";
import { formatDate, downloadCSV } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { DeleteConfirmationDialog } from "@/components/ui/delete-confirmation-dialog";

export default function ITEquipment() {
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const { toast } = useToast();

  // Fetch IT equipment
  const { data: equipment = [], isLoading } = useQuery({
    queryKey: ['/api/it-equipment'],
    queryFn: async () => {
      const response = await fetch('/api/it-equipment');
      if (!response.ok) throw new Error('Failed to fetch IT equipment');
      return response.json();
    },
  });

  // Create IT equipment mutation
  const createMutation = useMutation({
    mutationFn: async (data: any) => {
      try {
        // Validate data before sending
        if (!data || typeof data !== 'object') {
          throw new Error('Invalid data provided');
        }

        const response = await fetch('/api/it-equipment', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'include',
          body: JSON.stringify(data),
        });

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.message || 'Failed to create IT equipment');
        }

        return response.json();
      } catch (error) {
        console.error('Error creating IT equipment:', error);
        throw error;
      }
    },
    onSuccess: () => {
      setIsDialogOpen(false);
      queryClient.invalidateQueries({ queryKey: ['/api/it-equipment'] });
      toast({
        title: "Equipment added",
        description: "The IT equipment has been added successfully.",
      });
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: "There was an error adding the equipment. Please try again.",
        variant: "destructive",
      });
    }
  });

  const handleEquipmentSubmit = (data: any) => {
    createMutation.mutate(data);
  };

  const handleExportCSV = () => {
    if (equipment && equipment.length > 0) {
      const headers = Object.keys(equipment[0]); // Extract headers from the first item
      const csvData = equipment.map(item => headers.map(header => item[header]));
      downloadCSV(csvData, 'it_equipment.csv', headers);
    } else {
      toast({
        title: "No data to export",
        description: "There is no IT equipment data to export.",
      });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-gray-800">IT Equipment</h1>
          <p className="text-sm text-gray-600">Manage IT equipment inventory and assignments</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button onClick={handleExportCSV}>
            <DownloadIcon className="mr-2 h-4 w-4" />
            Export to CSV
          </Button>
          <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <PlusIcon className="mr-2 h-4 w-4" />
                Add Equipment
              </Button>
            </DialogTrigger>
            <DialogContent className="w-[95%] max-w-4xl max-h-[90vh] overflow-y-auto">
              <DialogHeader>
                <DialogTitle>Add IT Equipment</DialogTitle>
                <DialogDescription>
                  Enter the details for the IT equipment
                </DialogDescription>
              </DialogHeader>
              <ITEquipmentForm 
                onSubmit={handleEquipmentSubmit} 
                isLoading={createMutation.isPending} 
              />
            </DialogContent>
          </Dialog>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>IT Equipment Management</CardTitle>
          <CardDescription>Track and manage IT equipment inventory and assignments</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary"></div>
            </div>
          ) : equipment && equipment.length > 0 ? (
            <div className="grid gap-4">
              {equipment.map((item) => {
                const totalQuantity = item.totalQuantity || 0;
                const assignedQuantity = item.assignedQuantity || 0;
                const availableQuantity = totalQuantity - assignedQuantity;

                return (
                  <div key={item.id} className="p-4 border rounded-lg bg-white shadow-sm hover:shadow-md transition-shadow">
                    <div className="flex flex-col md:flex-row md:items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <MonitorIcon className="h-5 w-5 text-blue-600" />
                          <h3 className="font-semibold text-lg">{item.name}</h3>
                        </div>
                        <div className="space-y-1 text-sm text-gray-600">
                          <p><span className="font-medium">Category:</span> {item.category}</p>
                          <p><span className="font-medium">Model:</span> {item.model || 'N/A'}</p>
                          <p><span className="font-medium">Location:</span> {item.location || 'N/A'}</p>
                          <div className="flex gap-4">
                            <p><span className="font-medium">Total:</span> {totalQuantity}</p>
                            <p><span className="font-medium">Assigned:</span> {assignedQuantity}</p>
                            <p><span className="font-medium text-green-600">Available:</span> {availableQuantity}</p>
                          </div>
                          {item.dateAcquired && (
                            <div className="flex items-center gap-1">
                              <CalendarIcon className="h-3 w-3" />
                              <span className="font-medium">Acquired:</span> {formatDate(item.dateAcquired)}
                            </div>
                          )}
                        </div>
                      </div>
                      <div className="mt-4 md:mt-0 flex flex-col md:items-end gap-2">
                        <div className="flex flex-col items-end gap-2">
                          <Badge 
                            className={availableQuantity > 0 ? 'bg-green-100 text-green-800' : 
                                    availableQuantity === 0 ? 'bg-red-100 text-red-800' : 
                                    'bg-yellow-100 text-yellow-800'}
                          >
                            {availableQuantity > 0 ? 'Available' : 'Fully Assigned'}
                          </Badge>
                          {availableQuantity > 0 && (
                            <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200">
                              {availableQuantity} available
                            </Badge>
                          )}
                        </div>
                        <div className="flex gap-2 mt-2">
                          <Link href={`/it-equipment/${item.id}`}>
                            <Button variant="outline" size="sm">
                              View Details
                            </Button>
                          </Link>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-center py-10">
              <CheckCircleIcon className="h-16 w-16 mx-auto text-green-500 mb-4" />
              <h3 className="text-lg font-medium mb-2">IT Equipment Management Ready</h3>
              <p className="text-gray-500 mb-4">
                Click the "Add Equipment" button above to start tracking your IT equipment.
              </p>
              <div className="flex justify-center">
                <Link href="/">
                  <Button variant="outline">Return to Dashboard</Button>
                </Link>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}