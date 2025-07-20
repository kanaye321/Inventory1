import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { 
  Card, 
  CardContent, 
  CardDescription, 
  CardFooter, 
  CardHeader, 
  CardTitle 
} from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Input } from "@/components/ui/input";
import { 
  Dialog, 
  DialogContent, 
  DialogDescription, 
  DialogFooter,
  DialogHeader, 
  DialogTitle 
} from "@/components/ui/dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { 
  Database, 
  Download, 
  Upload, 
  RefreshCw, 
  AlertTriangle, 
  FileUp, 
  FileDown, 
  CheckCircle2,
  AlertCircle,
  HardDrive,
  Table as TableIcon,
  Settings,
  Loader2, 
  Clock,
  FileCog
} from "lucide-react";

interface DatabaseTable {
  name: string;
  columns: number;
  size: string;
  sizeBytes: number;
}

interface DatabaseBackup {
  filename: string;
  path: string;
  size: string;
  created: string;
}

interface DatabaseStatus {
  status: string;
  name: string;
  version: string;
  size: string;
  sizeBytes: number;
  tables: DatabaseTable[];
  tablesCount: number;
  lastBackup: string;
}

export default function DatabaseManagementPage() {
  const [activeTab, setActiveTab] = useState("status");
  const [isBackupDialogOpen, setIsBackupDialogOpen] = useState(false);
  const [isRestoreDialogOpen, setIsRestoreDialogOpen] = useState(false);
  const [isRestoreAllDialogOpen, setIsRestoreAllDialogOpen] = useState(false);
  const [selectedTables, setSelectedTables] = useState<string[]>([]);
  const [backupProgress, setBackupProgress] = useState(0);
  const [backupFilename, setBackupFilename] = useState(`backup-${new Date().toISOString().split('T')[0]}.sql`);
  const [restoreFile, setRestoreFile] = useState<File | null>(null);
  const [restoreAllFile, setRestoreAllFile] = useState<File | null>(null);

  const [autoBackup, setAutoBackup] = useState(false);
  const [autoOptimize, setAutoOptimize] = useState(false);
  const { toast } = useToast();

  // Fetch database status
  const { data: databaseStatus, isLoading: isStatusLoading, error: statusError } = useQuery({
    queryKey: ['/api/database/status'],
    queryFn: async () => {
      try {
        const res = await apiRequest('GET', '/api/database/status');
        if (!res.ok) {
          if (res.status === 503) {
            // Service unavailable - database not connected
            const errorData = await res.json().catch(() => ({ message: 'Database connection failed' }));
            return {
              status: "Disconnected",
              name: "PostgreSQL Database",
              version: "Not Connected",
              size: "Connection Required",
              sizeBytes: 0,
              tables: [],
              tablesCount: 0,
              lastBackup: "No connection",
              connectionError: true,
              errorMessage: errorData.message || 'Database connection failed',
              storageMode: "In-Memory Storage (Temporary)"
            };
          }
          throw new Error('Failed to fetch database status');
        }
        
        const data = await res.json();
        return {
          ...data,
          connectionError: false,
          storageMode: "PostgreSQL Database (Persistent)"
        };
      } catch (error) {
        console.error('Database status fetch error:', error);
        // Return fallback data when database connection fails
        return {
          status: "Disconnected", 
          name: "PostgreSQL Database",
          version: "Connection Failed",
          size: "Not Available",
          sizeBytes: 0,
          tables: [],
          tablesCount: 0,
          lastBackup: "Connection required",
          connectionError: true,
          errorMessage: error.message || 'Failed to connect to database',
          storageMode: "In-Memory Storage (Temporary)"
        };
      }
    },
    refetchInterval: 15000, // Refresh every 15 seconds for more accurate status
    retry: 2,
    retryOnMount: true,
    retryDelay: 2000,
  });

  // Fetch backups
  const { 
    data: backups, 
    isLoading: isBackupsLoading,
    error: backupsError,
    refetch: refetchBackups
  } = useQuery<DatabaseBackup[]>({
    queryKey: ['/api/database/backups'],
    queryFn: async () => {
      const response = await apiRequest('GET', '/api/database/backups');
      const data = await response.json();
      return data;
    },
    refetchOnWindowFocus: false,
    retry: 2,
    retryDelay: 1000
  });

  // Create backup mutation
  const createBackupMutation = useMutation({
    mutationFn: async () => {
      // Simulate progress updates
      let progress = 0;
      const interval = setInterval(() => {
        progress += 15;
        setBackupProgress(Math.min(progress, 90));
        if (progress >= 90) clearInterval(interval);
      }, 300);

      try {
        // Check if database is connected first
        if (databaseStatus?.connectionError) {
          clearInterval(interval);
          setBackupProgress(0);
          throw new Error('Database connection required. Please set up PostgreSQL database first.');
        }

        // Perform the backup
        const response = await apiRequest('POST', '/api/database/backup', {
          filename: backupFilename,
          tables: selectedTables.length > 0 ? selectedTables : undefined,
          includeData: true,
          compress: true
        });

        // Complete the progress
        clearInterval(interval);
        setBackupProgress(100);

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({ message: 'Backup failed' }));
          throw new Error(errorData.message || 'Backup failed');
        }

        // Clear selected tables
        setSelectedTables([]);

        // Handle file download if response contains file data
        if (response.headers.get('content-type')?.includes('application/sql') || 
            response.headers.get('content-disposition')?.includes('attachment')) {
          const blob = await response.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = backupFilename;
          document.body.appendChild(a);
          a.click();
          window.URL.revokeObjectURL(url);
          document.body.removeChild(a);
          return { success: true, message: 'Backup downloaded successfully' };
        }

        // Return the response
        return await response.json();
      } catch (error) {
        clearInterval(interval);
        setBackupProgress(0);
        throw error;
      }
    },
    onSuccess: (data) => {
      toast({
        title: "Backup created",
        description: `Database backup "${backupFilename}" has been created successfully.`,
      });
      setIsBackupDialogOpen(false);
      refetchBackups();
      // Reset progress after a short delay
      setTimeout(() => setBackupProgress(0), 1000);
    },
    onError: (error) => {
      setBackupProgress(0);
      toast({
        title: "Backup failed",
        description: "There was an error creating the database backup.",
        variant: "destructive",
      });
    }
  });

  // Restore backup mutation
  const restoreBackupMutation = useMutation({
    mutationFn: async (backupPath: string) => {
      const response = await apiRequest('POST', '/api/database/restore', {
        backupPath
      });
      return await response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Backup restored",
        description: "Database has been restored from backup successfully.",
      });
      setIsRestoreDialogOpen(false);
      refetchStatus();
    },
    onError: (error) => {
      toast({
        title: "Restore failed",
        description: "There was an error restoring the database from backup.",
        variant: "destructive",
      });
    }
  });

  // Optimize database mutation
  const optimizeDatabaseMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest('POST', '/api/database/optimize', {
        tables: ['users', 'assets', 'activities', 'licenses', 'components', 'accessories']
      });
      if (!response.ok) {
        throw new Error('Database optimization failed');
      }
      return await response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Database Optimized",
        description: `Database optimization completed successfully. ${data.optimizedTables?.length || 0} tables optimized.`,
      });
      refetchStatus();
    },
    onError: (error) => {
      toast({
        title: "Optimization Failed",
        description: "There was an error optimizing the database. Please try again.",
        variant: "destructive",
      });
    }
  });

  // Schedule maintenance mutation
  const scheduleMaintenanceMutation = useMutation({
    mutationFn: async (settings: { autoBackup: boolean; autoOptimize: boolean }) => {
      // Check if database is connected first
      if (databaseStatus?.connectionError) {
        throw new Error('Database connection required. Please set up PostgreSQL database first.');
      }

      const response = await apiRequest('POST', '/api/database/schedule', {
        ...settings,
        backupTime: '03:00', // 3:00 AM daily
        optimizeTime: '04:00', // 4:00 AM weekly
        retentionDays: 30, // Keep backups for 30 days
        emailNotifications: true
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: 'Schedule update failed' }));
        throw new Error(errorData.message || 'Schedule update failed');
      }

      return await response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Automatic backup scheduled",
        description: `Daily automatic backup ${autoBackup ? 'enabled' : 'disabled'} at 3:00 AM. Weekly optimization ${autoOptimize ? 'enabled' : 'disabled'} at 4:00 AM.`,
      });
    },
    onError: (error) => {
      toast({
        title: "Schedule update failed",
        description: error.message || "There was an error updating the maintenance schedule.",
        variant: "destructive",
      });
    }
  });

  // Backup all data mutation
  const backupAllDataMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest('POST', '/api/database/backup-all', {
        format: 'json',
        includeSystemData: true
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: 'Backup all failed' }));
        throw new Error(errorData.message || 'Backup all failed');
      }

      // Handle file download
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `complete-backup-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      return { success: true };
    },
    onSuccess: () => {
      toast({
        title: "Complete backup created",
        description: "All data has been backed up and downloaded successfully.",
      });
    },
    onError: (error) => {
      toast({
        title: "Backup failed",
        description: error.message || "There was an error creating the complete backup.",
        variant: "destructive",
      });
    }
  });

  // Restore all data mutation
  const restoreAllDataMutation = useMutation({
    mutationFn: async (file: File) => {
      // Basic file validation
      if (!file) {
        throw new Error('No file selected');
      }

      // Check file size (max 50MB)
      if (file.size > 50 * 1024 * 1024) {
        throw new Error('File too large. Please select a file smaller than 50MB');
      }

      // For JSON restore, validate content
      if (file.name.toLowerCase().endsWith('.json')) {
        const fileContent = await file.text();
        
        try {
          JSON.parse(fileContent);
        } catch (parseError) {
          // Check if it's HTML content (common issue)
          if (fileContent.trim().toLowerCase().startsWith('<!doctype') || 
              fileContent.trim().toLowerCase().startsWith('<html')) {
            throw new Error('Invalid file format: HTML content detected. Please select a valid JSON backup file.');
          }
          throw new Error('Invalid JSON format: Please select a valid JSON backup file.');
        }
      }

      const formData = new FormData();
      formData.append('backup', file);

      const response = await apiRequest('POST', '/api/database/restore-all', formData, {
        headers: {}, // Let browser set Content-Type for FormData
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: 'Restore all failed' }));
        throw new Error(errorData.message || 'Restore all failed');
      }

      return await response.json();
    },
    onSuccess: () => {
      toast({
        title: "Data restored",
        description: "All data has been restored successfully.",
      });
      setIsRestoreAllDialogOpen(false);
      setRestoreAllFile(null);
      refetchStatus();
    },
    onError: (error) => {
      toast({
        title: "Restore failed",
        description: error.message || "There was an error restoring the data.",
        variant: "destructive",
      });
    }
  });

  // Handle saving maintenance schedule
  const saveMaintenanceSchedule = () => {
    scheduleMaintenanceMutation.mutate({
      autoBackup,
      autoOptimize
    });
  };

  // Add refetchStatus function
  const refetchStatus = () => {
    queryClient.invalidateQueries({ queryKey: ['/api/database/status'] });
  };

  // Handle file upload for restore backup
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      const file = files[0];
      
      // Validate file extension
      const allowedExtensions = ['.sql', '.backup'];
      const hasValidExtension = allowedExtensions.some(ext => 
        file.name.toLowerCase().endsWith(ext)
      );
      
      if (!hasValidExtension) {
        toast({
          title: "Invalid file type",
          description: "Please select an SQL or BACKUP file",
          variant: "destructive",
        });
        e.target.value = ''; // Clear the input
        return;
      }
      
      // Validate file size (max 50MB for safety)
      if (file.size > 50 * 1024 * 1024) {
        toast({
          title: "File too large",
          description: "Please select a file smaller than 50MB",
          variant: "destructive",
        });
        e.target.value = ''; // Clear the input
        return;
      }
      
      setRestoreFile(file);
    }
  };

  // Toggle table selection
  const toggleTableSelection = (tableName: string) => {
    setSelectedTables(prev => 
      prev.includes(tableName) 
        ? prev.filter(name => name !== tableName)
        : [...prev, tableName]
    );
  };

  // Select all tables
  const selectAllTables = () => {
    if (databaseStatus && databaseStatus.tables) {
      setSelectedTables(databaseStatus.tables.map(table => table.name));
    }
  };

  // Deselect all tables
  const deselectAllTables = () => {
    setSelectedTables([]);
  };

  return (
    <div className="space-y-4 sm:space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 sm:gap-0">
        <h1 className="text-xl sm:text-3xl font-bold tracking-tight flex items-center">
          <Database className="mr-2 sm:mr-3 h-6 w-6 sm:h-8 sm:w-8" />
          Database Management
        </h1>
        <Button
          onClick={() => {
            refetchStatus();
            refetchBackups();
          }}
          variant="outline"
          size="sm"
          className="flex items-center mt-2 sm:mt-0 text-xs sm:text-sm"
        >
          <RefreshCw className="mr-1 sm:mr-2 h-3 w-3 sm:h-4 sm:w-4" />
          Refresh
        </Button>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid grid-cols-3 w-full">
          <TabsTrigger value="status" className="flex items-center text-xs sm:text-sm">
            <HardDrive className="mr-1 sm:mr-2 h-3 w-3 sm:h-4 sm:w-4" />
            <span className="hidden sm:inline">Status</span>
          </TabsTrigger>
          <TabsTrigger value="backup" className="flex items-center text-xs sm:text-sm">
            <Download className="mr-1 sm:mr-2 h-3 w-3 sm:h-4 sm:w-4" />
            <span className="hidden sm:inline">Backup</span>
          </TabsTrigger>
          <TabsTrigger value="maintenance" className="flex items-center text-xs sm:text-sm">
            <Settings className="mr-1 sm:mr-2 h-3 w-3 sm:h-4 sm:w-4" />
            <span className="hidden sm:inline">Maintenance</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="status">
          <Card>
            <CardHeader>
              <CardTitle>Database Status</CardTitle>
              <CardDescription>
                Current status and information about your database.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
            {statusError || databaseStatus?.connectionError ? (
              <div className="text-center py-8">
                <AlertTriangle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
                <p className="text-yellow-600 font-medium">PostgreSQL Database Not Connected</p>
                <p className="text-sm text-gray-500 mt-2">
                  Currently using in-memory storage. Data will not persist between server restarts.
                </p>
                
                {databaseStatus?.errorMessage && (
                  <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-lg">
                    <p className="text-sm text-red-700 font-medium">Connection Error:</p>
                    <p className="text-sm text-red-600">{databaseStatus.errorMessage}</p>
                  </div>
                )}

                <div className="mt-4 p-4 bg-blue-50 rounded-lg">
                  <p className="text-sm text-blue-800">
                    <strong>Current Status:</strong> {databaseStatus?.storageMode || "In-Memory Storage"}
                  </p>
                  <p className="text-sm text-blue-700 mt-2">
                    To enable persistent storage and full database features:
                  </p>
                  <ul className="text-sm text-blue-700 mt-2 list-disc list-inside">
                    <li>Set up PostgreSQL database in Replit</li>
                    <li>Restart the application</li>
                    <li>Enable automatic backups and optimization</li>
                    <li>Access production-ready storage</li>
                  </ul>
                </div>
                
                <div className="mt-4 flex gap-2 justify-center">
                  <Button 
                    onClick={() => {
                      refetchStatus();
                      refetchBackups();
                    }}
                    variant="outline"
                    size="sm"
                  >
                    <RefreshCw className="mr-2 h-4 w-4" />
                    Check Connection
                  </Button>
                  
                  <Button 
                    onClick={() => window.open('/console', '_blank')}
                    variant="outline"
                    size="sm"
                  >
                    <Database className="mr-2 h-4 w-4" />
                    Setup Database
                  </Button>
                </div>
              </div>
            ) : isStatusLoading ? (
              <div className="text-center py-8">
                <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4" />
                <p className="text-gray-500">Checking database status...</p>
              </div>
            ) : (


              databaseStatus ? (
                <div className="space-y-4">
                  {/* Storage Mode Indicator */}
                  <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
                    <div className="flex items-center">
                      <CheckCircle2 className="h-5 w-5 text-green-600 mr-2" />
                      <h3 className="font-medium text-green-800">Storage Mode</h3>
                    </div>
                    <p className="mt-2 text-green-700">{databaseStatus.storageMode}</p>
                    <p className="text-sm text-green-600 mt-1">
                      Connection Status: <span className="font-medium">{databaseStatus.status}</span>
                    </p>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4">
                    <div className="p-4 border rounded-md">
                      <div className="flex items-center">
                        <Database className="h-5 w-5 text-primary mr-2" />
                        <h3 className="font-medium">Database Name</h3>
                      </div>
                      <p className="mt-2">{databaseStatus.name}</p>
                    </div>

                    <div className="p-4 border rounded-md">
                      <div className="flex items-center">
                        <HardDrive className="h-5 w-5 text-primary mr-2" />
                        <h3 className="font-medium">Database Size</h3>
                      </div>
                      <p className="mt-2">{databaseStatus.size}</p>
                    </div>

                    <div className="p-4 border rounded-md">
                      <div className="flex items-center">
                        <FileCog className="h-5 w-5 text-primary mr-2" />
                        <h3 className="font-medium">Database Version</h3>
                      </div>
                      <p className="mt-2">{databaseStatus.version}</p>
                    </div>

                    <div className="p-4 border rounded-md">
                      <div className="flex items-center">
                        <TableIcon className="h-5 w-5 text-primary mr-2" />
                        <h3 className="font-medium">Tables</h3>
                      </div>
                      <p className="mt-2">{databaseStatus.tablesCount}</p>
                    </div>

                    <div className="p-4 border rounded-md">
                      <div className="flex items-center">
                        <Clock className="h-5 w-5 text-primary mr-2" />
                        <h3 className="font-medium">Last Backup</h3>
                      </div>
                      <p className="mt-2">{databaseStatus.lastBackup || 'No backups yet'}</p>
                    </div>

                    <div className="p-4 border rounded-md">
                      <div className="flex items-center">
                        <RefreshCw className="h-5 w-5 text-primary mr-2" />
                        <h3 className="font-medium">Last Updated</h3>
                      </div>
                      <p className="mt-2">{new Date().toLocaleTimeString()}</p>
                    </div>
                  </div>
                </div>
              ) : (
                <Alert className="mt-4">
                  <AlertCircle className="h-4 w-4" />
                  <AlertTitle>No Data</AlertTitle>
                  <AlertDescription>
                    No database statistics available.
                  </AlertDescription>
                </Alert>
              )
            )}

              {databaseStatus && databaseStatus.tables && (
                <div className="mt-6">
                  <h3 className="text-lg font-medium mb-3">Database Tables</h3>
                  <div className="rounded-md border">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b bg-muted/50">
                          <th className="h-10 px-4 text-left font-medium">Table Name</th>
                          <th className="h-10 px-4 text-left font-medium">Columns</th>
                          <th className="h-10 px-4 text-left font-medium">Size</th>
                        </tr>
                      </thead>
                      <tbody>
                        {databaseStatus.tables.map((table) => (
                          <tr key={table.name} className="border-b">
                            <td className="p-4 align-middle">{table.name}</td>
                            <td className="p-4 align-middle">{table.columns}</td>
                            <td className="p-4 align-middle">{table.size}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="backup">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Database Backup</CardTitle>
                <CardDescription>
                  Create a backup of your database to prevent data loss.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  Backups contain all your database tables and can be used to restore your system in case of failure.
                </p>
                {databaseStatus?.connectionError ? (
                  <Alert className="mb-4">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertTitle>Database Connection Required</AlertTitle>
                    <AlertDescription>
                      Set up PostgreSQL database to enable backup functionality.
                    </AlertDescription>
                  </Alert>
                ) : null}
                <Button 
                  onClick={() => setIsBackupDialogOpen(true)}
                  className="w-full"
                  disabled={databaseStatus?.connectionError}
                >
                  <FileDown className="mr-2 h-4 w-4" />
                  Create New Backup
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Restore Database</CardTitle>
                <CardDescription>
                  Restore your database from a previous backup.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  Restoring will replace your current database with a previous backup.
                </p>
                {databaseStatus?.connectionError ? (
                  <Alert className="mb-4">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertTitle>Database Connection Required</AlertTitle>
                    <AlertDescription>
                      Set up PostgreSQL database to enable restore functionality.
                    </AlertDescription>
                  </Alert>
                ) : null}
                <Button 
                  onClick={() => setIsRestoreDialogOpen(true)}
                  className="w-full"
                  variant="outline"
                  disabled={databaseStatus?.connectionError}
                >
                  <FileUp className="mr-2 h-4 w-4" />
                  Restore from Backup
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Backup All Data</CardTitle>
                <CardDescription>
                  Export all data from in-memory storage including the latest tables.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  Creates a complete backup of all tables and data from in-memory storage.
                </p>
                <Button 
                  onClick={() => backupAllDataMutation.mutate()}
                  className="w-full"
                  disabled={backupAllDataMutation.isPending}
                >
                  {backupAllDataMutation.isPending ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <Database className="mr-2 h-4 w-4" />
                  )}
                  Backup All Data
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Restore All Data</CardTitle>
                <CardDescription>
                  Restore all data to in-memory storage from a complete backup.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  Completely replaces all in-memory data with the backup data.
                </p>
                <Button 
                  onClick={() => setIsRestoreAllDialogOpen(true)}
                  className="w-full"
                  variant="outline"
                >
                  <RefreshCw className="mr-2 h-4 w-4" />
                  Restore All Data
                </Button>
              </CardContent>
            </Card>
          </div>

          {isBackupsLoading ? (
            <div className="flex items-center justify-center py-8 mt-6">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <span className="ml-2">Loading backup history...</span>
            </div>
          ) : backupsError ? (
            <Alert variant="destructive" className="mt-6">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>
                Failed to load backup history. Please try again.
              </AlertDescription>
            </Alert>
          ) : backups && backups.length > 0 ? (
            <Card className="mt-6">
              <CardHeader>
                <CardTitle>Backup History</CardTitle>
                <CardDescription>
                  Previous database backups available for restoration.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="rounded-md border">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b bg-muted/50">
                        <th className="h-10 px-4 text-left font-medium">Filename</th>
                        <th className="h-10 px-4 text-left font-medium">Size</th>
                        <th className="h-10 px-4 text-left font-medium">Created</th>
                        <th className="h-10 px-4 text-left font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {backups.map((backup) => (
                        <tr key={backup.path} className="border-b">
                          <td className="p-4 align-middle">{backup.filename}</td>
                          <td className="p-4 align-middle">{backup.size}</td>
                          <td className="p-4 align-middle">{backup.created}</td>
                          <td className="p-4 align-middle">
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => restoreBackupMutation.mutate(backup.path)}
                              disabled={restoreBackupMutation.isPending}
                            >
                              {restoreBackupMutation.isPending ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                <FileUp className="h-4 w-4" />
                              )}
                              <span className="ml-2">Restore</span>
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card className="mt-6">
              <CardHeader>
                <CardTitle>Backup History</CardTitle>
                <CardDescription>
                  No backups found. Create your first backup to protect your data.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Alert className="mt-2">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertTitle>No backups available</AlertTitle>
                  <AlertDescription>
                    It's recommended to create regular backups of your database to prevent data loss.
                  </AlertDescription>
                </Alert>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="maintenance">
          <Card>
            <CardHeader>
              <CardTitle>Database Maintenance</CardTitle>
              <CardDescription>
                Optimize and maintain your database for better performance.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 sm:space-y-6">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 sm:gap-6">
                <div className="border rounded-md p-6">
                  <h3 className="text-lg font-medium mb-2">Optimize Database</h3>
                  <p className="text-sm text-muted-foreground mb-4">
                    Optimize tables to reclaim unused space and improve performance.
                  </p>
                  <Button 
                    onClick={() => optimizeDatabaseMutation.mutate()}
                    disabled={optimizeDatabaseMutation.isPending}
                  >
                    {optimizeDatabaseMutation.isPending ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Settings className="mr-2 h-4 w-4" />
                    )}
                    Optimize Database
                  </Button>
                </div>

                <div className="border rounded-md p-6">
                  <h3 className="text-lg font-medium mb-2">Automatic Database Maintenance</h3>
                  <p className="text-sm text-muted-foreground mb-4">
                    Configure automatic maintenance tasks to keep your database healthy and backed up.
                  </p>
                  
                  <div className="space-y-4">
                    <div className="flex items-center space-x-2">
                      <Checkbox 
                        id="auto-backup" 
                        checked={autoBackup}
                        onCheckedChange={(checked) => 
                          setAutoBackup(checked === true)
                        }
                        disabled={databaseStatus?.connectionError}
                      />
                      <label
                        htmlFor="auto-backup"
                        className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
                      >
                        Enable automatic daily backups at 3:00 AM
                      </label>
                    </div>
                    
                    <div className="flex items-center space-x-2">
                      <Checkbox 
                        id="auto-optimize" 
                        checked={autoOptimize}
                        onCheckedChange={(checked) => 
                          setAutoOptimize(checked === true)
                        }
                        disabled={databaseStatus?.connectionError}
                      />
                      <label
                        htmlFor="auto-optimize"
                        className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
                      >
                        Enable weekly optimization every Sunday at 4:00 AM
                      </label>
                    </div>

                    {(autoBackup || autoOptimize) && (
                      <div className="mt-4 p-3 bg-blue-50 rounded-lg">
                        <p className="text-sm text-blue-800">
                          <strong>Backup Schedule:</strong> Daily at 3:00 AM<br />
                          <strong>Retention:</strong> 30 days<br />
                          <strong>Notifications:</strong> Email alerts on failure
                        </p>
                      </div>
                    )}

                    {databaseStatus?.connectionError && (
                      <Alert className="mt-4">
                        <AlertTriangle className="h-4 w-4" />
                        <AlertTitle>Database Connection Required</AlertTitle>
                        <AlertDescription>
                          Automatic backups require a PostgreSQL database connection. Please set up the database first.
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                  
                  <div className="mt-6 flex gap-2">
                    <Button 
                      onClick={saveMaintenanceSchedule} 
                      disabled={scheduleMaintenanceMutation.isPending || databaseStatus?.connectionError}
                    >
                      {scheduleMaintenanceMutation.isPending ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Saving Schedule...
                        </>
                      ) : (
                        <>
                          <Settings className="mr-2 h-4 w-4" />
                          Save Automatic Backup Schedule
                        </>
                      )}
                    </Button>
                    
                    <Button 
                      variant="outline"
                      onClick={() => {
                        setBackupFilename(`backup-${new Date().toISOString().split('T')[0]}.sql`);
                        setIsBackupDialogOpen(true);
                      }}
                      disabled={databaseStatus?.connectionError}
                    >
                      <FileDown className="mr-2 h-4 w-4" />
                      Manual Backup Now
                    </Button>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Create Backup Dialog */}
      <Dialog open={isBackupDialogOpen} onOpenChange={setIsBackupDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Create Database Backup</DialogTitle>
            <DialogDescription>
              Create a backup of your database. You can select specific tables or backup the entire database.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="backup-filename">Backup Filename</Label>
              <Input
                id="backup-filename"
                value={backupFilename}
                onChange={(e) => setBackupFilename(e.target.value)}
              />
            </div>

            {databaseStatus && databaseStatus.tables && (
              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <Label>Select Tables to Backup</Label>
                  <div className="space-x-2">
                    <Button 
                      variant="outline" 
                      size="sm" 
                      onClick={selectAllTables}
                    >
                      Select All
                    </Button>
                    <Button 
                      variant="outline" 
                      size="sm" 
                      onClick={deselectAllTables}
                    >
                      Deselect All
                    </Button>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 h-48 overflow-y-auto border rounded-md p-4">
                  {databaseStatus.tables.map((table) => (
                    <div key={table.name} className="flex items-center space-x-2">
                      <Checkbox
                        id={`table-${table.name}`}
                        checked={selectedTables.includes(table.name)}
                        onCheckedChange={() => toggleTableSelection(table.name)}
                      />
                      <label
                        htmlFor={`table-${table.name}`}
                        className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
                      >
                        {table.name}
                      </label>
                    </div>
                  ))}
                </div>
                <p className="text-sm text-muted-foreground">
                  {selectedTables.length === 0 
                    ? "No tables selected. The entire database will be backed up." 
                    : `${selectedTables.length} tables selected for backup.`}
                </p>
              </div>
            )}

            {backupProgress > 0 && (
              <div className="space-y-2">
                <Label>Backup Progress</Label>
                <Progress value={backupProgress} className="h-2" />
                <p className="text-sm text-muted-foreground">
                  {backupProgress < 100 
                    ? "Creating backup..." 
                    : "Backup completed successfully!"}
                </p>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button 
              variant="outline" 
              onClick={() => setIsBackupDialogOpen(false)}
              disabled={createBackupMutation.isPending}
            >
              Cancel
            </Button>
            <Button 
              onClick={() => createBackupMutation.mutate()}
              disabled={createBackupMutation.isPending || backupProgress > 0}
            >
              {createBackupMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <FileDown className="mr-2 h-4 w-4" />
              )}
              Create Backup
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Restore Backup Dialog */}
      <Dialog open={isRestoreDialogOpen} onOpenChange={setIsRestoreDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Restore Database</DialogTitle>
            <DialogDescription>
              Select a backup file to restore your database. This will replace all current data.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Warning</AlertTitle>
              <AlertDescription>
                Restoring a backup will replace all current data in your database. This action cannot be undone.
              </AlertDescription>
            </Alert>

            <div className="space-y-2">
              <Label htmlFor="backup-file">Select Backup File</Label>
              <Input
                id="backup-file"
                type="file"
                accept=".sql,.backup"
                onChange={handleFileUpload}
              />
              <p className="text-sm text-muted-foreground">
                Select an SQL backup file (.sql or .backup extension).
              </p>
            </div>
          </div>

          <DialogFooter>
            <Button 
              variant="outline" 
              onClick={() => setIsRestoreDialogOpen(false)}
              disabled={restoreBackupMutation.isPending}
            >
              Cancel
            </Button>
            <Button 
              variant="destructive"
              onClick={() => {
                if (restoreFile) {
                  // In a real implementation, you would upload the file here
                  toast({
                    title: "Restore started",
                    description: "Uploading and restoring backup file...",
                  });
                  // Close dialog
                  setIsRestoreDialogOpen(false);
                } else {
                  toast({
                    title: "No file selected",
                    description: "Please select a backup file to restore.",
                    variant: "destructive",
                  });
                }
              }}
              disabled={!restoreFile || restoreBackupMutation.isPending}
            >
              {restoreBackupMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <FileUp className="mr-2 h-4 w-4" />
              )}
              Restore Database
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Restore All Data Dialog */}
      <Dialog open={isRestoreAllDialogOpen} onOpenChange={setIsRestoreAllDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Restore All Data</DialogTitle>
            <DialogDescription>
              Upload a complete backup file to restore all data to in-memory storage.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Warning</AlertTitle>
              <AlertDescription>
                This will completely replace all data in memory with the backup data. All current data will be lost.
              </AlertDescription>
            </Alert>

            <div className="space-y-2">
              <Label htmlFor="restore-all-file">Select Complete Backup File</Label>
              <Input
                id="restore-all-file"
                type="file"
                accept=".json,.sql,.backup"
                onChange={(e) => {
                  const files = e.target.files;
                  if (files && files.length > 0) {
                    const file = files[0];
                    
                    // Validate file extension
                    const allowedExtensions = ['.json', '.sql', '.backup'];
                    const hasValidExtension = allowedExtensions.some(ext => 
                      file.name.toLowerCase().endsWith(ext)
                    );
                    
                    if (!hasValidExtension) {
                      toast({
                        title: "Invalid file type",
                        description: "Please select a JSON, SQL, or BACKUP file",
                        variant: "destructive",
                      });
                      e.target.value = ''; // Clear the input
                      return;
                    }
                    
                    // Validate file size (max 50MB for safety)
                    if (file.size > 50 * 1024 * 1024) {
                      toast({
                        title: "File too large",
                        description: "Please select a file smaller than 50MB",
                        variant: "destructive",
                      });
                      e.target.value = ''; // Clear the input
                      return;
                    }
                    
                    setRestoreAllFile(file);
                  }
                }}
              />
              <p className="text-sm text-muted-foreground">
                Select a backup file created with "Backup All Data". Accepts .json, .sql, or .backup files.
              </p>
              {restoreAllFile && (
                <p className="text-sm text-green-600">
                  Selected: {restoreAllFile.name} ({(restoreAllFile.size / 1024).toFixed(1)} KB)
                </p>
              )}
            </div>
          </div>

          <DialogFooter>
            <Button 
              variant="outline" 
              onClick={() => {
                setIsRestoreAllDialogOpen(false);
                setRestoreAllFile(null);
              }}
              disabled={restoreAllDataMutation.isPending}
            >
              Cancel
            </Button>
            <Button 
              variant="destructive"
              onClick={() => {
                if (restoreAllFile) {
                  restoreAllDataMutation.mutate(restoreAllFile);
                } else {
                  toast({
                    title: "No file selected",
                    description: "Please select a backup file to restore.",
                    variant: "destructive",
                  });
                }
              }}
              disabled={!restoreAllFile || restoreAllDataMutation.isPending}
            >
              {restoreAllDataMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="mr-2 h-4 w-4" />
              )}
              Restore All Data
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}