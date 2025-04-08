"""empty message

Revision ID: 19bd4f9596fc
Revises: aca83d09d145
Create Date: 2025-04-07 20:49:34.161888

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '19bd4f9596fc'
down_revision = 'aca83d09d145'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('post',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('titulo', sa.String(length=255), nullable=False),
    sa.Column('descripcion', sa.Text(), nullable=False),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('kilometros', sa.Float(), nullable=False),
    sa.Column('altura', sa.Integer(), nullable=False),
    sa.Column('lugar', sa.String(length=255), nullable=False),
    sa.Column('finaliza', sa.Date(), nullable=False),
    sa.Column('etapa', sa.Integer(), nullable=False),
    sa.Column('capacidad', sa.Integer(), nullable=False),
    sa.Column('hora', sa.Time(), nullable=False),
    sa.Column('salida', sa.Time(), nullable=False),
    sa.Column('dificultad', sa.String(length=50), nullable=False),
    sa.Column('sinpe', sa.String(length=255), nullable=False),
    sa.Column('coordinador', sa.String(length=255), nullable=False),
    sa.Column('precio', sa.Float(), nullable=False),
    sa.Column('limite_pago', sa.Date(), nullable=False),
    sa.Column('parqueo', sa.Boolean(), nullable=False),
    sa.Column('mascotas', sa.Boolean(), nullable=False),
    sa.Column('duchas', sa.Boolean(), nullable=False),
    sa.Column('banos', sa.Boolean(), nullable=False),
    sa.Column('imagen_post', sa.String(length=255), nullable=True),
    sa.Column('date_posted', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('post')
    # ### end Alembic commands ###
