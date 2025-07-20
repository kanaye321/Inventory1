import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { 
  Palette, 
  Settings as SettingsIcon, 
  Monitor, 
  Bell, 
  Shield, 
  Save,
  Loader2
} from "lucide-react";
import { apiRequest } from "@/lib/queryClient";

const colorThemes = [
  { name: "Default", value: "default", primary: "hsl(222.2 84% 4.9%)", secondary: "hsl(210 40% 98%)" },
  { name: "Blue", value: "blue", primary: "hsl(221.2 83.2% 53.3%)", secondary: "hsl(210 40% 98%)" },
  { name: "Green", value: "green", primary: "hsl(142.1 76.2% 36.3%)", secondary: "hsl(138 76% 97%)" },
  { name: "Purple", value: "purple", primary: "hsl(262.1 83.3% 57.8%)", secondary: "hsl(270 20% 98%)" },
  { name: "Red", value: "red", primary: "hsl(346.8 77.2% 49.8%)", secondary: "hsl(355 100% 97%)" },
  { name: "Orange", value: "orange", primary: "hsl(24.6 95% 53.1%)", secondary: "hsl(33 100% 97%)" },
  { name: "Yellow", value: "yellow", primary: "hsl(47.9 95.8% 53.1%)", secondary: "hsl(48 100% 97%)" },
  { name: "Pink", value: "pink", primary: "hsl(330.4 81.2% 60.4%)", secondary: "hsl(322 100% 97%)" },
];

export default function Settings() {
  const [theme, setTheme] = useState<"light" | "dark">(
    localStorage.getItem("theme") as "light" | "dark" || "light"
  );
  const [colorTheme, setColorTheme] = useState(
    localStorage.getItem("colorTheme") || "default"
  );

  // System settings state
  const [systemSettings, setSystemSettings] = useState({
    siteName: "",
    siteUrl: "",
    organizationName: "",
    adminEmail: "",
  });

  // Security settings state
  const [securitySettings, setSecuritySettings] = useState({
    enableTwoFactor: false,
    autoLogout: true,
    sessionTimeout: "30",
    passwordMinLength: "8",
    requirePasswordComplexity: true,
    maxLoginAttempts: "5",
  });

  // Notification settings state
  const [notificationSettings, setNotificationSettings] = useState({
    emailNotifications: true,
    lowStockAlerts: true,
    assetCheckoutAlerts: true,
  });

  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Fetch current settings
  const { data: settings, isLoading } = useQuery({
    queryKey: ['/api/settings'],
    queryFn: async () => {
      const response = await apiRequest('GET', '/api/settings');
      return await response.json();
    }
  });

  // Update settings mutation
  const updateSettingsMutation = useMutation({
    mutationFn: async (data: any) => {
      const response = await apiRequest('POST', '/api/settings', data);
      return await response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/settings'] });
      toast({
        title: "Settings Updated",
        description: "Your settings have been updated successfully.",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: "Failed to update settings. Please try again.",
        variant: "destructive",
      });
    }
  });

  const toggleTheme = () => {
    const newTheme = theme === "light" ? "dark" : "light";
    setTheme(newTheme);
    localStorage.setItem("theme", newTheme);
    document.documentElement.classList.toggle("dark", newTheme === "dark");

    toast({
      title: "Theme Updated",
      description: `Switched to ${newTheme} theme.`,
    });
  };

  const applyColorTheme = (themeName: string) => {
    setColorTheme(themeName);
    localStorage.setItem("colorTheme", themeName);

    const selectedTheme = colorThemes.find(t => t.value === themeName);
    if (selectedTheme) {
      document.documentElement.style.setProperty("--primary", selectedTheme.primary);
      document.documentElement.style.setProperty("--secondary", selectedTheme.secondary);
    }

    toast({
      title: "Theme Applied",
      description: `${selectedTheme?.name} theme has been applied.`,
    });
  };

  const saveSystemSettings = () => {
    updateSettingsMutation.mutate({
      ...systemSettings,
      companyName: systemSettings.organizationName,
      companyEmail: systemSettings.adminEmail,
    });
  };

  const saveSecuritySettings = () => {
    updateSettingsMutation.mutate({
      enableTwoFactor: securitySettings.enableTwoFactor,
      lockoutDuration: parseInt(securitySettings.sessionTimeout),
      passwordMinLength: parseInt(securitySettings.passwordMinLength),
      requireSpecialChar: securitySettings.requirePasswordComplexity,
      maxLoginAttempts: parseInt(securitySettings.maxLoginAttempts),
    });
  };

  const saveNotificationSettings = () => {
    updateSettingsMutation.mutate({
      enableAdminNotifications: notificationSettings.emailNotifications,
      notifyOnCheckout: notificationSettings.assetCheckoutAlerts,
      notifyOnCheckin: notificationSettings.assetCheckoutAlerts,
    });
  };

  // Update states when settings are loaded
  useEffect(() => {
    if (settings) {
      setSystemSettings({
        siteName: settings.siteName || "",
        siteUrl: settings.siteUrl || "",
        organizationName: settings.companyName || "",
        adminEmail: settings.companyEmail || "",
      });

      setSecuritySettings({
        enableTwoFactor: settings.enableTwoFactor || false,
        autoLogout: true,
        sessionTimeout: String(settings.lockoutDuration || 30),
        passwordMinLength: String(settings.passwordMinLength || 8),
        requirePasswordComplexity: settings.requireSpecialChar || true,
        maxLoginAttempts: String(settings.maxLoginAttempts || 5),
      });

      setNotificationSettings({
        emailNotifications: settings.enableAdminNotifications || true,
        lowStockAlerts: true,
        assetCheckoutAlerts: settings.notifyOnCheckout || true,
      });
    }
  }, [settings]);

  useEffect(() => {
    // Apply saved color theme on load
    const savedColorTheme = localStorage.getItem("colorTheme");
    if (savedColorTheme) {
      const selectedTheme = colorThemes.find(t => t.value === savedColorTheme);
      if (selectedTheme) {
        document.documentElement.style.setProperty("--primary", selectedTheme.primary);
        document.documentElement.style.setProperty("--secondary", selectedTheme.secondary);
      }
    }
  }, []);

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Settings</h1>
        <Badge variant="secondary">
          <SettingsIcon className="h-3 w-3 mr-1" />
          System Configuration
        </Badge>
      </div>

      <Tabs defaultValue="appearance" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="appearance">Appearance</TabsTrigger>
          <TabsTrigger value="system">System</TabsTrigger>
          <TabsTrigger value="notifications">Notifications</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
        </TabsList>

        <TabsContent value="appearance" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Palette className="h-5 w-5 mr-2" />
                Appearance Settings
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Theme Toggle */}
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="text-base">Dark Mode</Label>
                  <div className="text-sm text-muted-foreground">
                    Toggle between light and dark themes
                  </div>
                </div>
                <Switch
                  checked={theme === "dark"}
                  onCheckedChange={toggleTheme}
                />
              </div>

              <Separator />

              {/* Color Theme Selection */}
              <div className="space-y-4">
                <Label className="text-base">Color Theme</Label>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {colorThemes.map((themeOption) => (
                    <Button
                      key={themeOption.value}
                      variant={colorTheme === themeOption.value ? "default" : "outline"}
                      className="h-20 flex flex-col items-center justify-center"
                      onClick={() => applyColorTheme(themeOption.value)}
                    >
                      <div
                        className="w-6 h-6 rounded-full mb-2"
                        style={{ backgroundColor: themeOption.primary }}
                      />
                      <span className="text-xs">{themeOption.name}</span>
                    </Button>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="system" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Monitor className="h-5 w-5 mr-2" />
                System Settings
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="siteName">Site Name</Label>
                  <Input
                    id="siteName"
                    value={systemSettings.siteName}
                    onChange={(e) => setSystemSettings(prev => ({ ...prev, siteName: e.target.value }))}
                  />
                </div>
                <div>
                  <Label htmlFor="siteUrl">Site URL</Label>
                  <Input
                    id="siteUrl"
                    value={systemSettings.siteUrl}
                    onChange={(e) => setSystemSettings(prev => ({ ...prev, siteUrl: e.target.value }))}
                  />
                </div>
                <div>
                  <Label htmlFor="organizationName">Organization Name</Label>
                  <Input
                    id="organizationName"
                    value={systemSettings.organizationName}
                    onChange={(e) => setSystemSettings(prev => ({ ...prev, organizationName: e.target.value }))}
                  />
                </div>
                <div>
                  <Label htmlFor="adminEmail">Admin Email</Label>
                  <Input
                    id="adminEmail"
                    type="email"
                    value={systemSettings.adminEmail}
                    onChange={(e) => setSystemSettings(prev => ({ ...prev, adminEmail: e.target.value }))}
                  />
                </div>
              </div>
              <Button onClick={saveSystemSettings} disabled={updateSettingsMutation.isPending}>
                <Save className="h-4 w-4 mr-2" />
                {updateSettingsMutation.isPending ? "Saving..." : "Save System Settings"}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="notifications" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Bell className="h-5 w-5 mr-2" />
                Notification Settings
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="text-base">Email Notifications</Label>
                  <div className="text-sm text-muted-foreground">
                    Receive email notifications for system events
                  </div>
                </div>
                <Switch 
                  checked={notificationSettings.emailNotifications}
                  onCheckedChange={(checked) => 
                    setNotificationSettings(prev => ({ ...prev, emailNotifications: checked }))
                  }
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="text-base">Low Stock Alerts</Label>
                  <div className="text-sm text-muted-foreground">
                    Get notified when inventory is running low
                  </div>
                </div>
                <Switch 
                  checked={notificationSettings.lowStockAlerts}
                  onCheckedChange={(checked) => 
                    setNotificationSettings(prev => ({ ...prev, lowStockAlerts: checked }))
                  }
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="text-base">Asset Checkout Alerts</Label>
                  <div className="text-sm text-muted-foreground">
                    Notifications for asset checkouts and returns
                  </div>
                </div>
                <Switch 
                  checked={notificationSettings.assetCheckoutAlerts}
                  onCheckedChange={(checked) => 
                    setNotificationSettings(prev => ({ ...prev, assetCheckoutAlerts: checked }))
                  }
                />
              </div>

              <Button onClick={saveNotificationSettings} disabled={updateSettingsMutation.isPending}>
                <Save className="h-4 w-4 mr-2" />
                {updateSettingsMutation.isPending ? "Saving..." : "Save Notification Settings"}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Shield className="h-5 w-5 mr-2" />
                Security Settings
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="text-base">Two-Factor Authentication</Label>
                  <div className="text-sm text-muted-foreground">
                    Add an extra layer of security to your account
                  </div>
                </div>
                <Switch 
                  checked={securitySettings.enableTwoFactor}
                  onCheckedChange={(checked) => 
                    setSecuritySettings(prev => ({ ...prev, enableTwoFactor: checked }))
                  }
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="text-base">Auto-logout</Label>
                  <div className="text-sm text-muted-foreground">
                    Automatically logout after period of inactivity
                  </div>
                </div>
                <Switch 
                  checked={securitySettings.autoLogout}
                  onCheckedChange={(checked) => 
                    setSecuritySettings(prev => ({ ...prev, autoLogout: checked }))
                  }
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <Label>Session Timeout (minutes)</Label>
                  <Select 
                    value={securitySettings.sessionTimeout} 
                    onValueChange={(value) => 
                      setSecuritySettings(prev => ({ ...prev, sessionTimeout: value }))
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="15">15 minutes</SelectItem>
                      <SelectItem value="30">30 minutes</SelectItem>
                      <SelectItem value="60">1 hour</SelectItem>
                      <SelectItem value="120">2 hours</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label>Minimum Password Length</Label>
                  <Input
                    type="number"
                    min="6"
                    max="20"
                    value={securitySettings.passwordMinLength}
                    onChange={(e) => 
                      setSecuritySettings(prev => ({ ...prev, passwordMinLength: e.target.value }))
                    }
                  />
                </div>

                <div>
                  <Label>Maximum Login Attempts</Label>
                  <Input
                    type="number"
                    min="3"
                    max="10"
                    value={securitySettings.maxLoginAttempts}
                    onChange={(e) => 
                      setSecuritySettings(prev => ({ ...prev, maxLoginAttempts: e.target.value }))
                    }
                  />
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="text-base">Password Complexity</Label>
                  <div className="text-sm text-muted-foreground">
                    Require uppercase, lowercase, numbers, and special characters
                  </div>
                </div>
                <Switch 
                  checked={securitySettings.requirePasswordComplexity}
                  onCheckedChange={(checked) => 
                    setSecuritySettings(prev => ({ ...prev, requirePasswordComplexity: checked }))
                  }
                />
              </div>

              <Button onClick={saveSecuritySettings} disabled={updateSettingsMutation.isPending}>
                <Save className="h-4 w-4 mr-2" />
                {updateSettingsMutation.isPending ? "Saving..." : "Save Security Settings"}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}