import React, { createContext, useContext, useReducer } from "react";
import type { ReactNode } from "react";
import { authAPI, type LoginRequest } from "../lib/api";

interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  isAuthenticated: boolean;
  mfaEnabled: boolean;
}

interface AuthState {
  user: User | null;
  loading: boolean;
  error: string | null;
  requireMFA: boolean;
}

type AuthAction =
  | { type: "LOGIN_START" }
  | { type: "LOGIN_SUCCESS"; payload: User }
  | { type: "LOGIN_FAILURE"; payload: string }
  | { type: "REQUIRE_MFA" }
  | { type: "LOGOUT" }
  | { type: "CLEAR_ERROR" };

const initialState: AuthState = {
  user: null,
  loading: false,
  error: null,
  requireMFA: false,
};

const authReducer = (state: AuthState, action: AuthAction): AuthState => {
  switch (action.type) {
    case "LOGIN_START":
      return { ...state, loading: true, error: null };
    case "LOGIN_SUCCESS":
      return {
        ...state,
        loading: false,
        error: null,
        user: action.payload,
        requireMFA: false,
      };
    case "LOGIN_FAILURE":
      return {
        ...state,
        loading: false,
        error: action.payload,
        user: null,
      };
    case "REQUIRE_MFA":
      return { ...state, loading: false, requireMFA: true, error: null };
    case "LOGOUT":
      return initialState;
    case "CLEAR_ERROR":
      return { ...state, error: null };
    default:
      return state;
  }
};

interface AuthContextType {
  state: AuthState;
  login: (email: string, password: string, mfaCode?: string) => Promise<void>;
  logout: () => void;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, initialState);

  const login = async (email: string, password: string, mfaCode?: string) => {
    dispatch({ type: "LOGIN_START" });

    try {
      const credentials: LoginRequest = { email, password };
      if (mfaCode) {
        credentials.mfaCode = mfaCode;
      }

      const response = await authAPI.login(credentials);

      if (response.success && response.data) {
        const user: User = {
          ...response.data.user,
          isAuthenticated: true,
          mfaEnabled: true, // Assume MFA is enabled for demo
        };
        dispatch({ type: "LOGIN_SUCCESS", payload: user });
      } else if (response.requiresMFA) {
        dispatch({ type: "REQUIRE_MFA" });
      } else {
        dispatch({
          type: "LOGIN_FAILURE",
          payload: response.error || "Login failed",
        });
      }
    } catch (error: any) {
      dispatch({
        type: "LOGIN_FAILURE",
        payload: error.message || "Network error",
      });
    }
  };

  const logout = async () => {
    try {
      await authAPI.logout();
    } catch (error) {
      console.error("Logout error:", error);
    } finally {
      dispatch({ type: "LOGOUT" });
    }
  };

  const clearError = () => {
    dispatch({ type: "CLEAR_ERROR" });
  };

  return (
    <AuthContext.Provider value={{ state, login, logout, clearError }}>
      {children}
    </AuthContext.Provider>
  );
};
