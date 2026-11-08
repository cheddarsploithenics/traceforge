import type { MouseEvent } from "react";

import { BrandMark, Icon, type IconName } from "../components/Icon";
import type { Route } from "../lib/route";

const NAV: { route: Route; label: string; icon: IconName }[] = [
  { route: "overview", label: "Overview", icon: "overview" },
  { route: "assets", label: "Assets", icon: "assets" },
  { route: "scans", label: "Scans", icon: "scans" },
  { route: "projects", label: "Projects", icon: "projects" },
];

interface SidebarProps {
  route: Route;
  onNavigate: (route: Route) => void;
  version: string | null;
}

export function Sidebar({ route, onNavigate, version }: SidebarProps) {
  const go = (target: Route) => (event: MouseEvent) => {
    event.preventDefault();
    onNavigate(target);
  };
  return (
    <nav className="sidebar" aria-label="Main">
      <a className="sidebar__brand" href="#/overview" onClick={go("overview")}>
        <BrandMark />
        <span className="sidebar__text">TraceForge</span>
      </a>
      <ul className="sidebar__nav">
        {NAV.map((item) => (
          <li key={item.route}>
            <a
              href={`#/${item.route}`}
              className="sidebar__link"
              aria-current={route === item.route ? "page" : undefined}
              onClick={go(item.route)}
            >
              <Icon name={item.icon} />
              <span className="sidebar__text">{item.label}</span>
            </a>
          </li>
        ))}
      </ul>
      <div className="sidebar__footer">
        <Icon name="shield" size={14} />
        <span className="sidebar__text">
          Localhost only
          {version && <span className="sidebar__version">v{version}</span>}
        </span>
      </div>
    </nav>
  );
}
