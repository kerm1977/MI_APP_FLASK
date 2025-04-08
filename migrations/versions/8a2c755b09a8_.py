"""empty message

Revision ID: 8a2c755b09a8
Revises: 152202e037b9
Create Date: 2025-04-07 21:36:38.310312

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8a2c755b09a8'
down_revision = '152202e037b9'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('publicacion')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('publicacion',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('title', sa.VARCHAR(length=255), nullable=True),
    sa.Column('note', sa.TEXT(), nullable=True),
    sa.Column('conten', sa.TEXT(), nullable=True),
    sa.Column('klm', sa.INTEGER(), nullable=True),
    sa.Column('altur', sa.INTEGER(), nullable=True),
    sa.Column('place', sa.VARCHAR(length=255), nullable=True),
    sa.Column('end', sa.DATE(), nullable=True),
    sa.Column('etapa', sa.VARCHAR(length=255), nullable=True),
    sa.Column('capacidad', sa.INTEGER(), nullable=True),
    sa.Column('hora', sa.TIME(), nullable=True),
    sa.Column('salida', sa.VARCHAR(length=255), nullable=True),
    sa.Column('dificultad', sa.VARCHAR(length=255), nullable=True),
    sa.Column('sinpe', sa.VARCHAR(length=255), nullable=True),
    sa.Column('coordinador', sa.VARCHAR(length=255), nullable=True),
    sa.Column('precio', sa.FLOAT(), nullable=True),
    sa.Column('limite_pago', sa.DATE(), nullable=True),
    sa.Column('parqueo', sa.BOOLEAN(), nullable=True),
    sa.Column('mascotas', sa.BOOLEAN(), nullable=True),
    sa.Column('duchas', sa.BOOLEAN(), nullable=True),
    sa.Column('banos', sa.BOOLEAN(), nullable=True),
    sa.Column('imagen', sa.VARCHAR(length=255), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###
