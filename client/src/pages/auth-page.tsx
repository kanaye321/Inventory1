
import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { useAuth } from "@/hooks/use-auth";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { EyeIcon, EyeOffIcon, LockIcon, ShieldCheckIcon, UsersIcon, TrendingUpIcon, BarChart3Icon } from "lucide-react";

export default function AuthPage() {
  const [activeTab, setActiveTab] = useState<string>("login");
  const [, setLocation] = useLocation();
  const { user, login } = useAuth();
  const { toast } = useToast();

  // Login form state
  const [loginData, setLoginData] = useState({
    username: "",
    password: "",
  });
  const [showPassword, setShowPassword] = useState(false);
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  // Register form state
  const [registerData, setRegisterData] = useState({
    username: "",
    password: "",
    confirmPassword: "",
    firstName: "",
    lastName: "",
    email: "",
    department: "",
  });
  const [showRegisterPassword, setShowRegisterPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isRegistering, setIsRegistering] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoggingIn(true);

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(loginData),
      });

      if (response.ok) {
        const userData = await response.json();
        login(userData);
        toast({
          title: "Login successful",
          description: `Welcome back, ${userData.firstName || userData.username}!`,
        });
        setLocation('/');
      } else {
        const errorData = await response.json();
        toast({
          title: "Login failed",
          description: errorData.message || "Invalid credentials",
          variant: "destructive",
        });
      }
    } catch (error) {
      toast({
        title: "Login failed",
        description: "Network error. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsLoggingIn(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (registerData.password !== registerData.confirmPassword) {
      toast({
        title: "Registration failed",
        description: "Passwords do not match",
        variant: "destructive",
      });
      return;
    }

    setIsRegistering(true);

    try {
      const response = await fetch('/api/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          username: registerData.username,
          password: registerData.password,
          firstName: registerData.firstName,
          lastName: registerData.lastName,
          email: registerData.email,
          department: registerData.department,
        }),
      });

      if (response.ok) {
        const userData = await response.json();
        login(userData);
        toast({
          title: "Registration successful",
          description: `Welcome, ${userData.firstName || userData.username}!`,
        });
        setLocation('/');
      } else {
        const errorData = await response.json();
        toast({
          title: "Registration failed",
          description: errorData.message || "Registration failed",
          variant: "destructive",
        });
      }
    } catch (error) {
      toast({
        title: "Registration failed",
        description: "Network error. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsRegistering(false);
    }
  };

  // If user is already logged in, redirect to dashboard
  if (user) {
    return null;
  }

  return (
    <div className="min-h-screen bg-[#1a1d23] flex overflow-hidden">
      {/* Left Side - Branding and Features */}
      <div className="flex-1 flex flex-col justify-center px-8 lg:px-16 py-12 animate-fade-in-left">
        {/* Header */}
        <div className="mb-16 space-y-8">
          <div className="flex items-center mb-8 animate-bounce-in delay-300">
            <div className="w-3 h-3 bg-green-500 rounded-full mr-4 animate-pulse"></div>
            <span className="text-green-500 text-sm font-semibold tracking-widest uppercase">Welcome !</span>
          </div>
          
          <div className="space-y-6">
            <h1 className="text-white font-bold leading-tight animate-slide-up delay-500">
              <span className="text-5xl lg:text-7xl text-green-500 block animate-glow !text-green-500">SRPH</span>
              <span className="text-4xl lg:text-6xl text-white block">Inventory</span>
              <span className="text-4xl lg:text-6xl text-gray-400 block">Management</span>
            </h1>
            <p className="text-gray-400 text-lg lg:text-xl max-w-lg leading-relaxed animate-fade-in delay-1000">
              Advanced asset management system designed for modern organizations. Streamline your inventory workflow with powerful tools and insights.
            </p>
          </div>
        </div>

        {/* Features Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 animate-stagger-in delay-1200">
          <div className="flex items-start space-x-5 group cursor-pointer">
            <div className="w-10 h-10 bg-green-500/20 rounded-xl flex items-center justify-center flex-shrink-0 mt-1 group-hover:bg-green-500/30 transition-all duration-300 group-hover:scale-110">
              <ShieldCheckIcon className="w-5 h-5 text-green-500" />
            </div>
            <div>
              <h3 className="text-white font-semibold mb-3 text-lg group-hover:text-green-400 transition-colors">Secure Asset Tracking</h3>
              <p className="text-gray-400 text-sm leading-relaxed">
                End-to-end encryption and secure access controls
              </p>
            </div>
          </div>

          <div className="flex items-start space-x-5 group cursor-pointer">
            <div className="w-10 h-10 bg-yellow-500/20 rounded-xl flex items-center justify-center flex-shrink-0 mt-1 group-hover:bg-yellow-500/30 transition-all duration-300 group-hover:scale-110">
              <TrendingUpIcon className="w-5 h-5 text-yellow-500" />
            </div>
            <div>
              <h3 className="text-white font-semibold mb-3 text-lg group-hover:text-yellow-400 transition-colors">Real-time Updates</h3>
              <p className="text-gray-400 text-sm leading-relaxed">
                Live inventory updates and instant notifications
              </p>
            </div>
          </div>

          <div className="flex items-start space-x-5 group cursor-pointer">
            <div className="w-10 h-10 bg-blue-500/20 rounded-xl flex items-center justify-center flex-shrink-0 mt-1 group-hover:bg-blue-500/30 transition-all duration-300 group-hover:scale-110">
              <UsersIcon className="w-5 h-5 text-blue-500" />
            </div>
            <div>
              <h3 className="text-white font-semibold mb-3 text-lg group-hover:text-blue-400 transition-colors">Team Collaboration</h3>
              <p className="text-gray-400 text-sm leading-relaxed">
                Multi-user support with role-based permissions
              </p>
            </div>
          </div>

          <div className="flex items-start space-x-5 group cursor-pointer">
            <div className="w-10 h-10 bg-purple-500/20 rounded-xl flex items-center justify-center flex-shrink-0 mt-1 group-hover:bg-purple-500/30 transition-all duration-300 group-hover:scale-110">
              <BarChart3Icon className="w-5 h-5 text-purple-500" />
            </div>
            <div>
              <h3 className="text-white font-semibold mb-3 text-lg group-hover:text-purple-400 transition-colors">Advanced Analytics</h3>
              <p className="text-gray-400 text-sm leading-relaxed">
                Comprehensive reports and data insights
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Right Side - Auth Form */}
      <div className="w-full lg:w-[520px] flex items-center justify-center px-6 lg:px-12 py-16 animate-fade-in-right">
        <div className="w-full max-w-md">
          <Card className="bg-[#2a2f36]/95 backdrop-blur-sm border-gray-700/50 shadow-2xl animate-scale-in delay-800 hover:shadow-green-500/10 transition-all duration-500">
            <CardHeader className="text-center pb-8 pt-10">
              <div className="w-16 h-16 bg-green-500/20 rounded-2xl flex items-center justify-center mx-auto mb-6 animate-pulse-glow">
                <LockIcon className="w-8 h-8 text-green-500" />
              </div>
              <h2 className="text-green-500 text-2xl font-bold mb-3 animate-fade-in delay-1000">Welcome Back</h2>
              <p className="text-gray-400 text-base animate-fade-in delay-1200">Sign in to access your inventory management dashboard</p>
            </CardHeader>

            <CardContent className="space-y-8 px-10 pb-10">
              <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                <TabsList className="grid w-full grid-cols-2 bg-[#1a1d23] border border-gray-700/50 mb-8 h-12 rounded-xl overflow-hidden">
                  <TabsTrigger 
                    value="login" 
                    className="text-gray-400 data-[state=active]:text-white data-[state=active]:bg-gradient-to-r data-[state=active]:from-green-600 data-[state=active]:to-green-500 border-r border-gray-700/50 transition-all duration-300 font-medium"
                  >
                    Sign In
                  </TabsTrigger>
                  <TabsTrigger 
                    value="register" 
                    className="text-gray-400 data-[state=active]:text-white data-[state=active]:bg-gradient-to-r data-[state=active]:from-green-600 data-[state=active]:to-green-500 transition-all duration-300 font-medium"
                  >
                    Create Account
                  </TabsTrigger>
                </TabsList>

                <TabsContent value="login" className="space-y-6 animate-fade-in">
                  <form onSubmit={handleLogin} className="space-y-6">
                    <div className="space-y-3">
                      <Label htmlFor="username" className="text-gray-300 text-sm font-medium">
                        Username
                      </Label>
                      <Input
                        id="username"
                        type="text"
                        placeholder="Enter your username"
                        className="bg-[#1a1d23] border-gray-600 text-white placeholder-gray-500 focus:border-green-500 focus:ring-2 focus:ring-green-500/20 h-12 rounded-lg transition-all duration-300 hover:border-gray-500"
                        value={loginData.username}
                        onChange={(e) => setLoginData({ ...loginData, username: e.target.value })}
                        required
                      />
                    </div>

                    <div className="space-y-3">
                      <Label htmlFor="password" className="text-gray-300 text-sm font-medium">
                        Password
                      </Label>
                      <div className="relative">
                        <Input
                          id="password"
                          type={showPassword ? "text" : "password"}
                          placeholder="Enter your password"
                          className="bg-[#1a1d23] border-gray-600 text-white placeholder-gray-500 focus:border-green-500 focus:ring-2 focus:ring-green-500/20 pr-12 h-12 rounded-lg transition-all duration-300 hover:border-gray-500"
                          value={loginData.password}
                          onChange={(e) => setLoginData({ ...loginData, password: e.target.value })}
                          required
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="absolute right-3 top-1/2 -translate-y-1/2 h-8 w-8 text-gray-400 hover:text-gray-300 hover:bg-gray-700/50 rounded-md transition-all duration-200"
                          onClick={() => setShowPassword(!showPassword)}
                        >
                          {showPassword ? (
                            <EyeOffIcon className="h-4 w-4" />
                          ) : (
                            <EyeIcon className="h-4 w-4" />
                          )}
                        </Button>
                      </div>
                    </div>

                    <Button 
                      type="submit" 
                      className="w-full bg-gradient-to-r from-green-600 to-green-500 hover:from-green-700 hover:to-green-600 text-white font-semibold h-12 rounded-lg shadow-lg hover:shadow-green-500/25 transform hover:scale-[1.02] transition-all duration-300 mt-8"
                      disabled={isLoggingIn}
                    >
                      {isLoggingIn ? (
                        <>
                          <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-3"></div>
                          <span>Signing In...</span>
                        </>
                      ) : (
                        <>
                          <LockIcon className="mr-3 h-5 w-5" />
                          Sign In
                        </>
                      )}
                    </Button>

                    <p className="text-xs text-gray-500 text-center mt-6 leading-relaxed">
                      By continuing, you agree to our{" "}
                      <span className="text-green-400 cursor-pointer hover:text-green-300 hover:underline transition-colors">Terms of Service</span>{" "}
                      and{" "}
                      <span className="text-green-400 cursor-pointer hover:text-green-300 hover:underline transition-colors">Privacy Policy</span>
                    </p>
                  </form>
                </TabsContent>

                <TabsContent value="register" className="space-y-5 animate-fade-in">
                  <form onSubmit={handleRegister} className="space-y-5">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label htmlFor="firstName" className="text-gray-300 text-sm font-medium">
                          First Name
                        </Label>
                        <Input
                          id="firstName"
                          type="text"
                          placeholder="John"
                          className="bg-[#1a1d23] border-gray-600 text-white placeholder-gray-500 focus:border-green-500 focus:ring-2 focus:ring-green-500/20 h-11 rounded-lg transition-all duration-300 hover:border-gray-500"
                          value={registerData.firstName}
                          onChange={(e) => setRegisterData({ ...registerData, firstName: e.target.value })}
                          required
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="lastName" className="text-gray-300 text-sm font-medium">
                          Last Name
                        </Label>
                        <Input
                          id="lastName"
                          type="text"
                          placeholder="Doe"
                          className="bg-[#1a1d23] border-gray-600 text-white placeholder-gray-500 focus:border-green-500 focus:ring-2 focus:ring-green-500/20 h-11 rounded-lg transition-all duration-300 hover:border-gray-500"
                          value={registerData.lastName}
                          onChange={(e) => setRegisterData({ ...registerData, lastName: e.target.value })}
                          required
                        />
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="email" className="text-gray-300 text-sm font-medium">
                        Email Address
                      </Label>
                      <Input
                        id="email"
                        type="email"
                        placeholder="john.doe@company.com"
                        className="bg-[#1a1d23] border-gray-600 text-white placeholder-gray-500 focus:border-green-500 focus:ring-2 focus:ring-green-500/20 h-11 rounded-lg transition-all duration-300 hover:border-gray-500"
                        value={registerData.email}
                        onChange={(e) => setRegisterData({ ...registerData, email: e.target.value })}
                        required
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="department" className="text-gray-300 text-sm font-medium">
                        Department
                      </Label>
                      <Input
                        id="department"
                        type="text"
                        placeholder="IT Department"
                        className="bg-[#1a1d23] border-gray-600 text-white placeholder-gray-500 focus:border-green-500 focus:ring-2 focus:ring-green-500/20 h-11 rounded-lg transition-all duration-300 hover:border-gray-500"
                        value={registerData.department}
                        onChange={(e) => setRegisterData({ ...registerData, department: e.target.value })}
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="regUsername" className="text-gray-300 text-sm font-medium">
                        Username
                      </Label>
                      <Input
                        id="regUsername"
                        type="text"
                        placeholder="Choose a username"
                        className="bg-[#1a1d23] border-gray-600 text-white placeholder-gray-500 focus:border-green-500 focus:ring-2 focus:ring-green-500/20 h-11 rounded-lg transition-all duration-300 hover:border-gray-500"
                        value={registerData.username}
                        onChange={(e) => setRegisterData({ ...registerData, username: e.target.value })}
                        required
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="regPassword" className="text-gray-300 text-sm font-medium">
                        Password
                      </Label>
                      <div className="relative">
                        <Input
                          id="regPassword"
                          type={showRegisterPassword ? "text" : "password"}
                          placeholder="Create a strong password"
                          className="bg-[#1a1d23] border-gray-600 text-white placeholder-gray-500 focus:border-green-500 focus:ring-2 focus:ring-green-500/20 pr-12 h-11 rounded-lg transition-all duration-300 hover:border-gray-500"
                          value={registerData.password}
                          onChange={(e) => setRegisterData({ ...registerData, password: e.target.value })}
                          required
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="absolute right-3 top-1/2 -translate-y-1/2 h-7 w-7 text-gray-400 hover:text-gray-300 hover:bg-gray-700/50 rounded-md transition-all duration-200"
                          onClick={() => setShowRegisterPassword(!showRegisterPassword)}
                        >
                          {showRegisterPassword ? (
                            <EyeOffIcon className="h-4 w-4" />
                          ) : (
                            <EyeIcon className="h-4 w-4" />
                          )}
                        </Button>
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="confirmPassword" className="text-gray-300 text-sm font-medium">
                        Confirm Password
                      </Label>
                      <div className="relative">
                        <Input
                          id="confirmPassword"
                          type={showConfirmPassword ? "text" : "password"}
                          placeholder="Confirm your password"
                          className="bg-[#1a1d23] border-gray-600 text-white placeholder-gray-500 focus:border-green-500 focus:ring-2 focus:ring-green-500/20 pr-12 h-11 rounded-lg transition-all duration-300 hover:border-gray-500"
                          value={registerData.confirmPassword}
                          onChange={(e) => setRegisterData({ ...registerData, confirmPassword: e.target.value })}
                          required
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="absolute right-3 top-1/2 -translate-y-1/2 h-7 w-7 text-gray-400 hover:text-gray-300 hover:bg-gray-700/50 rounded-md transition-all duration-200"
                          onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                        >
                          {showConfirmPassword ? (
                            <EyeOffIcon className="h-4 w-4" />
                          ) : (
                            <EyeIcon className="h-4 w-4" />
                          )}
                        </Button>
                      </div>
                    </div>

                    <Button 
                      type="submit" 
                      className="w-full bg-gradient-to-r from-green-600 to-green-500 hover:from-green-700 hover:to-green-600 text-white font-semibold h-12 rounded-lg shadow-lg hover:shadow-green-500/25 transform hover:scale-[1.02] transition-all duration-300 mt-6"
                      disabled={isRegistering}
                    >
                      {isRegistering ? (
                        <>
                          <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-3"></div>
                          Creating account...
                        </>
                      ) : (
                        "Create Account"
                      )}
                    </Button>

                    <p className="text-xs text-gray-500 text-center mt-5 leading-relaxed">
                      By continuing, you agree to our{" "}
                      <span className="text-green-400 cursor-pointer hover:text-green-300 hover:underline transition-colors">Terms of Service</span>{" "}
                      and{" "}
                      <span className="text-green-400 cursor-pointer hover:text-green-300 hover:underline transition-colors">Privacy Policy</span>
                    </p>
                  </form>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
