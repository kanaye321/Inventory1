

import { useEffect, useState } from "react";
import { useParams, Link, useLocation } from "wouter";
import { useQuery, useMutation } from "@tanstack/react-query";
import { 
  Card, 
  CardContent, 
  CardDescription, 
  CardHeader, 
  CardTitle 
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { formatDate } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Progress } from "@/components/ui/progress";
import {
  ChevronLeftIcon,
  EditIcon,
  TrashIcon,
  CalendarIcon,
  MonitorIcon,
  UsersIcon,
  BuildingIcon,
  ServerIcon,
  PlusIcon,
  UserIcon,
  PackageIcon
} from "lucide-react";
import ITEquipmentForm from "@/components/it-equipment/it-equipment-form";

export default function ITEquipmentDetails() {
  const params = useParams<{ id: string }>();
  const id = parseInt(params.id);
  const [, navigate] = useLocation();
  const { toast } = useToast();
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false);
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);
  const [isAssignDialogOpen, setIsAssignDialogOpen] = useState(false);

  // Fetch equipment details
  const { data: equipment, isLoading, isError } = useQuery({
    queryKey: [`/api/it-equipment/${id}`],
    queryFn: async () => {
      const response = await fetch(`/api/it-equipment/${id}`);
      if (!response.ok) throw new Error('Failed to fetch equipment');
      return response.json();
    },
  });
  
  // Fetch equipment assignments
  const { data: equipmentAssignments = [] } = useQuery({
    queryKey: [`/api/it-equipment/${id}/assignments`],
    queryFn: async () => {
      const response = await fetch(`/api/it-equipment/${id}/assignments`);
      if (!response.ok) throw new Error('Failed to fetch equipment assignments');
      return response.json();
    },
    enabled: !!equipment,
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: async () => {
      return apiRequest('DELETE', `/api/it-equipment/${id}`);
    },
    onSuccess: () => {
      toast({
        title: "Equipment deleted",
        description: "The equipment has been deleted successfully.",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/it-equipment'] });
      navigate('/it-equipment');
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: "There was an error deleting the equipment. Please try again.",
        variant: "destructive",
      });
    }
  });

  // Update mutation
  const updateMutation = useMutation({
    mutationFn: async (data: any) => {
      return apiRequest('PATCH', `/api/it-equipment/${id}`, data);
    },
    onSuccess: () => {
      setIsEditDialogOpen(false);
      toast({
        title: "Equipment updated",
        description: "The equipment has been updated successfully.",
      });
      queryClient.invalidateQueries({ queryKey: [`/api/it-equipment/${id}`] });
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: "There was an error updating the equipment. Please try again.",
        variant: "destructive",
      });
    }
  });

  // Handle equipment update
  const handleUpdate = (data: any) => {
    updateMutation.mutate(data);
  };

  // Handle equipment delete
  const handleDelete = () => {
    deleteMutation.mutate();
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (isError || !equipment) {
    return (
      <div className="text-center py-10">
        <h3 className="text-lg font-medium mb-2">Error Loading Equipment</h3>
        <p className="text-gray-500 mb-4">
          There was a problem loading the equipment details.
        </p>
        <Link href="/it-equipment">
          <Button>Return to IT Equipment</Button>
        </Link>
      </div>
    );
  }

  const totalQuantity = equipment.totalQuantity || 0;
  const assignedQuantity = equipment.assignedQuantity || 0;
  const availableQuantity = totalQuantity - assignedQuantity;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <div className="flex items-center mb-2">
            <Link href="/it-equipment">
              <Button variant="ghost" size="sm" className="-ml-3">
                <ChevronLeftIcon className="mr-1 h-4 w-4" />
                Back to IT Equipment
              </Button>
            </Link>
          </div>
          <h1 className="text-2xl font-semibold text-gray-800">{equipment.name}</h1>
          <div className="flex items-center gap-2 mt-1">
            <Badge 
              className={availableQuantity > 0 ? 'bg-green-100 text-green-800' : 
                      availableQuantity === 0 ? 'bg-red-100 text-red-800' : 
                      'bg-yellow-100 text-yellow-800'}
            >
              {availableQuantity > 0 ? 'Available' : 'Fully Assigned'}
            </Badge>
            <span className="text-sm text-gray-500">Model: <span className="font-mono">{equipment.model}</span></span>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Dialog open={isEditDialogOpen} onOpenChange={setIsEditDialogOpen}>
            <DialogTrigger asChild>
              <Button variant="outline">
                <EditIcon className="mr-2 h-4 w-4" />
                Edit
              </Button>
            </DialogTrigger>
            <DialogContent className="w-[95%] max-w-4xl max-h-[90vh] overflow-y-auto">
              <DialogHeader>
                <DialogTitle>Edit IT Equipment</DialogTitle>
                <DialogDescription>
                  Update the equipment details
                </DialogDescription>
              </DialogHeader>
              <ITEquipmentForm 
                onSubmit={handleUpdate} 
                isLoading={updateMutation.isPending}
                defaultValues={{
                  name: equipment.name,
                  category: equipment.category,
                  totalQuantity: equipment.totalQuantity,
                  assignedQuantity: equipment.assignedQuantity,
                  model: equipment.model,
                  location: equipment.location,
                  dateAcquired: equipment.dateAcquired,
                  knoxId: equipment.knoxId,
                  serialNumber: equipment.serialNumber,
                  dateRelease: equipment.dateRelease,
                  remarks: equipment.remarks,
                }}
              />
            </DialogContent>
          </Dialog>
          <Dialog open={isDeleteDialogOpen} onOpenChange={setIsDeleteDialogOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" className="text-red-500 border-red-200 hover:text-red-600 hover:bg-red-50">
                <TrashIcon className="mr-2 h-4 w-4" />
                Delete
              </Button>
            </DialogTrigger>
            <DialogContent className="w-[95%] max-w-md max-h-[90vh] overflow-y-auto">
              <DialogHeader>
                <DialogTitle>Delete Equipment</DialogTitle>
                <DialogDescription>
                  Are you sure you want to delete this equipment? This action cannot be undone.
                </DialogDescription>
              </DialogHeader>
              <div className="flex items-center justify-end space-x-2 mt-4">
                <Button variant="outline" onClick={() => setIsDeleteDialogOpen(false)}>Cancel</Button>
                <Button 
                  variant="destructive" 
                  onClick={handleDelete}
                  disabled={deleteMutation.isPending}
                >
                  {deleteMutation.isPending ? "Deleting..." : "Delete Equipment"}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>
      
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Equipment Details</CardTitle>
              <CardDescription>Details about the IT equipment</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-3">
                  <div>
                    <h3 className="text-sm font-medium text-gray-500 flex items-center">
                      <ServerIcon className="mr-2 h-4 w-4" />
                      Equipment Name
                    </h3>
                    <p className="mt-1">{equipment.name}</p>
                  </div>
                  
                  <div>
                    <h3 className="text-sm font-medium text-gray-500 flex items-center">
                      <PackageIcon className="mr-2 h-4 w-4" />
                      Category
                    </h3>
                    <p className="mt-1">{equipment.category}</p>
                  </div>
                  
                  <div>
                    <h3 className="text-sm font-medium text-gray-500 flex items-center">
                      <MonitorIcon className="mr-2 h-4 w-4" />
                      Model
                    </h3>
                    <p className="mt-1">{equipment.model || 'Not specified'}</p>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <div>
                    <h3 className="text-sm font-medium text-gray-500 flex items-center">
                      <CalendarIcon className="mr-2 h-4 w-4" />
                      Date Acquired
                    </h3>
                    <p className="mt-1">{equipment.dateAcquired ? formatDate(equipment.dateAcquired) : 'Not specified'}</p>
                  </div>
                  
                  <div>
                    <h3 className="text-sm font-medium text-gray-500 flex items-center">
                      <BuildingIcon className="mr-2 h-4 w-4" />
                      Location
                    </h3>
                    <p className="mt-1">{equipment.location || 'Not specified'}</p>
                  </div>
                  
                  <div>
                    <h3 className="text-sm font-medium text-gray-500 flex items-center">
                      <UsersIcon className="mr-2 h-4 w-4" />
                      Quantities
                    </h3>
                    <div className="mt-1 flex items-center gap-2">
                      <span>Total: {totalQuantity}</span>
                      <Badge variant="outline" className="ml-1">
                        {assignedQuantity} assigned
                      </Badge>
                      {availableQuantity > 0 && (
                        <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200">
                          {availableQuantity} available
                        </Badge>
                      )}
                    </div>
                  </div>
                </div>
              </div>
              
              <Separator />
              
              <div>
                <h3 className="text-sm font-medium text-gray-500">Remarks</h3>
                <p className="mt-1 text-gray-700 whitespace-pre-wrap">
                  {equipment.remarks || 'No remarks provided.'}
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
        
        <div className="space-y-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Equipment Assignments</CardTitle>
                <CardDescription>Track who is using this equipment</CardDescription>
              </div>
              {availableQuantity > 0 && (
                <Dialog open={isAssignDialogOpen} onOpenChange={setIsAssignDialogOpen}>
                  <DialogTrigger asChild>
                    <Button size="sm">
                      <PlusIcon className="h-4 w-4 mr-2" />
                      Assign Equipment
                    </Button>
                  </DialogTrigger>
                  <DialogContent className="w-[95%] max-w-md max-h-[90vh] overflow-y-auto">
                    <DialogHeader>
                      <DialogTitle>Assign Equipment</DialogTitle>
                      <DialogDescription>
                        Assign this equipment to someone.
                      </DialogDescription>
                    </DialogHeader>
                    
                    <form onSubmit={(e) => {
                      e.preventDefault();
                      const formData = new FormData(e.currentTarget);
                      const assignedTo = formData.get('assignedTo') as string;
                      const knoxId = formData.get('knoxId') as string;
                      const serialNumber = formData.get('serialNumber') as string;
                      const quantity = parseInt(formData.get('quantity') as string) || 1;
                      const notes = formData.get('notes') as string || null;
                      
                      if (!assignedTo) {
                        toast({
                          title: "Error",
                          description: "Assignment information is required",
                          variant: "destructive"
                        });
                        return;
                      }

                      if (quantity > availableQuantity) {
                        toast({
                          title: "Error",
                          description: `Only ${availableQuantity} units available`,
                          variant: "destructive"
                        });
                        return;
                      }
                      
                      // Create equipment assignment
                      const assignmentData = {
                        equipmentId: equipment.id,
                        assignedTo,
                        knoxId,
                        serialNumber,
                        quantity,
                        notes,
                        assignedDate: new Date().toISOString().split('T')[0]
                      };
                      
                      // First create the equipment assignment
                      apiRequest('POST', `/api/it-equipment/${id}/assign`, assignmentData)
                        .then(() => {
                          // If successful, update the equipment with new assignment count
                          const newAssignedQuantity = assignedQuantity + quantity;
                          
                          return updateMutation.mutateAsync({
                            assignedQuantity: newAssignedQuantity
                          });
                        })
                        .then(() => {
                          setIsAssignDialogOpen(false);
                          toast({
                            title: "Success",
                            description: `Equipment assigned to: ${assignedTo}`,
                          });
                          // Invalidate both equipment and assignment queries
                          queryClient.invalidateQueries({ queryKey: [`/api/it-equipment/${id}`] });
                          queryClient.invalidateQueries({ queryKey: [`/api/it-equipment/${id}/assignments`] });
                        })
                        .catch(() => {
                          toast({
                            title: "Error",
                            description: "Failed to assign equipment",
                            variant: "destructive"
                          });
                        });
                    }}>
                      <div className="grid gap-4 py-4">
                        <div className="grid grid-cols-4 items-center gap-4">
                          <Label htmlFor="assignedTo" className="text-right">
                            Assigned to
                          </Label>
                          <Input 
                            id="assignedTo" 
                            name="assignedTo"
                            className="col-span-3" 
                            placeholder="Enter the assigned user's name"
                            required
                          />
                        </div>
                        
                        <div className="grid grid-cols-4 items-center gap-4">
                          <Label htmlFor="quantity" className="text-right">
                            Quantity
                          </Label>
                          <Input 
                            id="quantity" 
                            name="quantity"
                            type="number"
                            min="1"
                            max={availableQuantity}
                            defaultValue="1"
                            className="col-span-3" 
                            placeholder="Enter quantity"
                            required
                          />
                        </div>

                        <div className="grid grid-cols-4 items-center gap-4">
                          <Label htmlFor="knoxId" className="text-right">
                            Knox ID
                          </Label>
                          <Input 
                            id="knoxId" 
                            name="knoxId"
                            className="col-span-3" 
                            placeholder="Enter Knox ID (optional)"
                          />
                        </div>

                        <div className="grid grid-cols-4 items-center gap-4">
                          <Label htmlFor="serialNumber" className="text-right">
                            Serial Number
                          </Label>
                          <Input 
                            id="serialNumber" 
                            name="serialNumber"
                            className="col-span-3" 
                            placeholder="Enter serial number (optional)"
                          />
                        </div>
                        
                        <div className="grid grid-cols-4 items-center gap-4">
                          <Label htmlFor="notes" className="text-right">
                            Notes
                          </Label>
                          <Textarea
                            id="notes"
                            name="notes"
                            className="col-span-3"
                            placeholder="Optional notes about this assignment"
                            rows={3}
                          />
                        </div>
                      </div>
                      
                      <DialogFooter>
                        <Button type="submit" disabled={updateMutation.isPending}>
                          {updateMutation.isPending ? "Assigning..." : "Assign Equipment"}
                        </Button>
                      </DialogFooter>
                    </form>
                  </DialogContent>
                </Dialog>
              )}
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex justify-between mb-2">
                  <div>
                    <span className="text-sm font-medium text-gray-500">Total Quantity</span>
                    <p className="font-semibold">{totalQuantity}</p>
                  </div>
                  <div>
                    <span className="text-sm font-medium text-gray-500">Assigned</span>
                    <p className="font-semibold">{assignedQuantity}</p>
                  </div>
                  <div>
                    <span className="text-sm font-medium text-gray-500">Available</span>
                    <p className="font-semibold">{availableQuantity}</p>
                  </div>
                </div>
                
                {totalQuantity > 0 && (
                  <Progress 
                    value={totalQuantity > 0 ? (assignedQuantity / totalQuantity) * 100 : 0} 
                    className="h-2"
                  />
                )}
                
                {/* Equipment assignments */}
                <div className="mt-4">
                  <h3 className="text-sm font-medium mb-2">All Assigned Users</h3>
                  
                  {equipmentAssignments.length > 0 ? (
                    <div className="space-y-2">
                      {equipmentAssignments.map((assignment) => (
                        <div key={assignment.id} className="p-3 border rounded-md">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center">
                              <UserIcon className="h-4 w-4 mr-2 text-gray-500" />
                              <div>
                                <p className="font-medium">{assignment.assignedTo}</p>
                                <p className="text-xs text-gray-500">
                                  Assigned on {formatDate(assignment.assignedDate)} • Qty: {assignment.quantity}
                                </p>
                                {assignment.knoxId && (
                                  <p className="text-xs text-gray-500">Knox ID: {assignment.knoxId}</p>
                                )}
                                {assignment.serialNumber && (
                                  <p className="text-xs text-gray-500">S/N: {assignment.serialNumber}</p>
                                )}
                              </div>
                            </div>
                            {assignment.notes && (
                              <Badge variant="outline" className="ml-auto mr-2">
                                Has notes
                              </Badge>
                            )}
                          </div>
                          {assignment.notes && (
                            <div className="mt-2 text-sm text-gray-600 bg-gray-50 p-2 rounded">
                              {assignment.notes}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-4 border rounded-md border-dashed">
                      <p className="text-gray-500">No assignments found</p>
                    </div>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

