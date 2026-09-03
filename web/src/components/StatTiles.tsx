import { Card, CardBody } from '@patternfly/react-core';

export type StatTone = 'brand' | 'green' | 'red' | 'orange' | 'grey';

export interface StatTileItem {
  label: string;
  value: number | string;
  tone?: StatTone;
}

export function StatTiles({ items }: { items: StatTileItem[] }) {
  return (
    <div className="pb-stat-tiles">
      {items.map((item) => {
        const tone = item.tone && item.tone !== 'brand' ? ` pb-stat-tile--${item.tone}` : '';
        return (
          <Card key={item.label} isCompact isFullHeight className={`pb-stat-tile${tone}`}>
            <CardBody className="pb-stat-tile__body">
              <p className="pb-stat-tile__value">{item.value}</p>
              <p className="pb-stat-tile__label">{item.label}</p>
            </CardBody>
          </Card>
        );
      })}
    </div>
  );
}
