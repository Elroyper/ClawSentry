import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { TRANSLATIONS, type TranslationKey } from './locales'

export type Language = 'en' | 'zh'
export type Theme = 'light' | 'dark'

type PreferencesContextValue = {
  language: Language
  setLanguage: (language: Language) => void
  theme: Theme
  setTheme: (theme: Theme) => void
  toggleLanguage: () => void
  toggleTheme: () => void
  t: (key: TranslationKey) => string
}

const STORAGE_LANGUAGE = 'clawsentry.language'
const STORAGE_THEME = 'clawsentry.theme'

const PreferencesContext = createContext<PreferencesContextValue | null>(null)

function readStoredLanguage(): Language {
  if (typeof window === 'undefined') return 'en'
  return window.localStorage.getItem(STORAGE_LANGUAGE) === 'zh' ? 'zh' : 'en'
}

function readStoredTheme(): Theme {
  if (typeof window === 'undefined') return 'dark'
  return window.localStorage.getItem(STORAGE_THEME) === 'light' ? 'light' : 'dark'
}

export function PreferencesProvider({ children }: { children: ReactNode }) {
  const [language, setLanguageState] = useState<Language>(readStoredLanguage)
  const [theme, setThemeState] = useState<Theme>(readStoredTheme)

  const setLanguage = (nextLanguage: Language) => {
    setLanguageState(nextLanguage)
    window.localStorage.setItem(STORAGE_LANGUAGE, nextLanguage)
  }

  const setTheme = (nextTheme: Theme) => {
    setThemeState(nextTheme)
    window.localStorage.setItem(STORAGE_THEME, nextTheme)
  }

  useEffect(() => {
    document.documentElement.lang = language === 'zh' ? 'zh-CN' : 'en'
  }, [language])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    document.documentElement.style.colorScheme = theme
  }, [theme])

  const value = useMemo<PreferencesContextValue>(() => ({
    language,
    setLanguage,
    theme,
    setTheme,
    toggleLanguage: () => setLanguage(language === 'zh' ? 'en' : 'zh'),
    toggleTheme: () => setTheme(theme === 'dark' ? 'light' : 'dark'),
    t: key => TRANSLATIONS[language][key] ?? TRANSLATIONS.en[key] ?? key,
  }), [language, theme])

  return <PreferencesContext.Provider value={value}>{children}</PreferencesContext.Provider>
}

export function usePreferences() {
  const value = useContext(PreferencesContext)
  return value ?? {
    language: 'en',
    setLanguage: () => {},
    theme: 'dark',
    setTheme: () => {},
    toggleLanguage: () => {},
    toggleTheme: () => {},
    t: key => TRANSLATIONS.en[key] ?? key,
  }
}
