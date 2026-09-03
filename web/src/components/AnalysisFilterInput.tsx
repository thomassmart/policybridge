import { useEffect, useId, useMemo, useRef, useState } from 'react';
import {
  Menu,
  MenuContent,
  MenuItem,
  MenuList,
  SearchInput,
} from '@patternfly/react-core';
import {
  matchAnalysisFilterSuggestions,
  type AnalysisFilterSuggestion,
} from '@/utils/analysisFilterSuggestions';

interface AnalysisFilterInputProps {
  id?: string;
  value: string;
  onChange: (value: string) => void;
  suggestions: AnalysisFilterSuggestion[];
  placeholder?: string;
  'aria-label'?: string;
}

export function AnalysisFilterInput({
  id = 'analysis-filter',
  value,
  onChange,
  suggestions,
  placeholder = 'Filter rules and connections…',
  'aria-label': ariaLabel = 'Filter DFW rules and connectivity map',
}: AnalysisFilterInputProps) {
  const listboxId = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);

  const matches = useMemo(
    () => matchAnalysisFilterSuggestions(suggestions, value),
    [suggestions, value],
  );

  useEffect(() => {
    setActiveIndex(matches.length ? 0 : -1);
  }, [matches]);

  const closeMenu = () => {
    setOpen(false);
    setActiveIndex(-1);
  };

  const selectSuggestion = (next: string) => {
    onChange(next);
    closeMenu();
  };

  const handleKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (!open && (event.key === 'ArrowDown' || event.key === 'ArrowUp') && matches.length) {
      setOpen(true);
      setActiveIndex(0);
      event.preventDefault();
      return;
    }

    if (!open || !matches.length) {
      if (event.key === 'Escape') closeMenu();
      return;
    }

    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setActiveIndex((prev) => (prev + 1) % matches.length);
      return;
    }

    if (event.key === 'ArrowUp') {
      event.preventDefault();
      setActiveIndex((prev) => (prev <= 0 ? matches.length - 1 : prev - 1));
      return;
    }

    if (event.key === 'Enter' && activeIndex >= 0) {
      event.preventDefault();
      selectSuggestion(matches[activeIndex].value);
      return;
    }

    if (event.key === 'Escape') {
      event.preventDefault();
      closeMenu();
    }
  };

  useEffect(() => {
    const onPointerDown = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) {
        closeMenu();
      }
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, []);

  const showMenu = open && value.trim().length > 0 && matches.length > 0;

  return (
    <div className="pb-analysis-filter" ref={rootRef}>
      <SearchInput
        searchInputId={id}
        placeholder={placeholder}
        value={value}
        onChange={(_event, next) => {
          onChange(next);
          setOpen(next.trim().length > 0);
        }}
        onClear={() => {
          onChange('');
          closeMenu();
        }}
        inputProps={{
          onFocus: () => {
            if (value.trim()) setOpen(true);
          },
          onKeyDown: handleKeyDown,
          'aria-expanded': showMenu,
          'aria-controls': showMenu ? listboxId : undefined,
          'aria-autocomplete': 'list',
          role: 'combobox',
        }}
        aria-label={ariaLabel}
      />
      {showMenu ? (
        <Menu
          className="pb-analysis-filter__menu"
          isScrollable
          isPlain
          onSelect={(_event, itemId) => {
            const match = matches.find((s) => `${s.group}:${s.value}` === itemId);
            if (match) selectSuggestion(match.value);
          }}
        >
          <MenuContent>
            <MenuList id={listboxId} role="listbox">
              {matches.map((suggestion, index) => (
                <MenuItem
                  key={`${suggestion.group}:${suggestion.value}`}
                  itemId={`${suggestion.group}:${suggestion.value}`}
                  isActive={index === activeIndex}
                  description={suggestion.group}
                  onClick={() => selectSuggestion(suggestion.value)}
                >
                  {suggestion.label}
                </MenuItem>
              ))}
            </MenuList>
          </MenuContent>
        </Menu>
      ) : null}
    </div>
  );
}
