"""webhook scoped flows and destinations

Revision ID: b7c2d8f41901
Revises: a11559d361ea
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'b7c2d8f41901'
down_revision: Union[str, Sequence[str], None] = 'a11559d361ea'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('destinations') as batch:
        batch.add_column(sa.Column('endpoint_id', sa.Integer(), nullable=True))
        batch.create_index('ix_destinations_endpoint_id', ['endpoint_id'])
        batch.create_foreign_key('fk_destinations_endpoint_id', 'incoming_endpoints', ['endpoint_id'], ['id'], ondelete='CASCADE')
    op.add_column('flows', sa.Column('mode', sa.String(length=20), nullable=False, server_default='conditional'))
    op.create_table(
        'route_mappings',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('route_id', sa.Integer(), sa.ForeignKey('flow_destinations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('position', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('target_path', sa.String(length=300), nullable=False),
        sa.Column('source_type', sa.String(length=30), nullable=False, server_default='field'),
        sa.Column('source_value', sa.Text(), nullable=False, server_default=''),
        sa.Column('static_type', sa.String(length=30), nullable=False, server_default='string'),
        sa.Column('fallback_json', sa.JSON(), nullable=True),
        sa.Column('transforms', sa.JSON(), nullable=False, server_default='[]'),
    )
    op.create_index('ix_route_mappings_route_id', 'route_mappings', ['route_id'])

    # Existing destinations were global. If one was used by multiple incoming
    # webhooks, clone it per endpoint and repoint only that endpoint's routes.
    # This preserves behavior while establishing the new ownership model.
    bind = op.get_bind()
    meta = sa.MetaData()
    destinations = sa.Table('destinations', meta, autoload_with=bind)
    flows = sa.Table('flows', meta, autoload_with=bind)
    routes = sa.Table('flow_destinations', meta, autoload_with=bind)
    pairs = bind.execute(
        sa.select(routes.c.destination_id, flows.c.endpoint_id)
        .select_from(routes.join(flows, routes.c.flow_id == flows.c.id))
        .distinct()
        .order_by(routes.c.destination_id, flows.c.endpoint_id)
    ).all()
    grouped = {}
    for destination_id, endpoint_id in pairs:
        grouped.setdefault(destination_id, []).append(endpoint_id)
    for destination_id, endpoint_ids in grouped.items():
        endpoint_ids = list(dict.fromkeys(endpoint_ids))
        if not endpoint_ids:
            continue
        bind.execute(destinations.update().where(destinations.c.id == destination_id).values(endpoint_id=endpoint_ids[0]))
        for endpoint_id in endpoint_ids[1:]:
            source = dict(bind.execute(sa.select(destinations).where(destinations.c.id == destination_id)).mappings().one())
            source.pop('id', None)
            source['endpoint_id'] = endpoint_id
            result = bind.execute(destinations.insert().values(**source))
            new_id = result.inserted_primary_key[0]
            flow_ids = sa.select(flows.c.id).where(flows.c.endpoint_id == endpoint_id)
            bind.execute(
                routes.update()
                .where(routes.c.destination_id == destination_id, routes.c.flow_id.in_(flow_ids))
                .values(destination_id=new_id)
            )


def downgrade() -> None:
    op.drop_index('ix_route_mappings_route_id', table_name='route_mappings')
    op.drop_table('route_mappings')
    op.drop_column('flows', 'mode')
    with op.batch_alter_table('destinations') as batch:
        batch.drop_constraint('fk_destinations_endpoint_id', type_='foreignkey')
        batch.drop_index('ix_destinations_endpoint_id')
        batch.drop_column('endpoint_id')
