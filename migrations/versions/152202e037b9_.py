"""empty message

Revision ID: 152202e037b9
Revises: 19bd4f9596fc
Create Date: 2025-04-07 21:21:29.480029

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '152202e037b9'
down_revision = '19bd4f9596fc'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('post')
    op.drop_table('contacto')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('contacto',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('nombre', sa.VARCHAR(length=100), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('post',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('titulo', sa.VARCHAR(length=255), nullable=False),
    sa.Column('descripcion', sa.TEXT(), nullable=False),
    sa.Column('content', sa.TEXT(), nullable=False),
    sa.Column('kilometros', sa.FLOAT(), nullable=False),
    sa.Column('altura', sa.INTEGER(), nullable=False),
    sa.Column('lugar', sa.VARCHAR(length=255), nullable=False),
    sa.Column('finaliza', sa.DATE(), nullable=False),
    sa.Column('etapa', sa.INTEGER(), nullable=False),
    sa.Column('capacidad', sa.INTEGER(), nullable=False),
    sa.Column('hora', sa.TIME(), nullable=False),
    sa.Column('salida', sa.TIME(), nullable=False),
    sa.Column('dificultad', sa.VARCHAR(length=50), nullable=False),
    sa.Column('sinpe', sa.VARCHAR(length=255), nullable=False),
    sa.Column('coordinador', sa.VARCHAR(length=255), nullable=False),
    sa.Column('precio', sa.FLOAT(), nullable=False),
    sa.Column('limite_pago', sa.DATE(), nullable=False),
    sa.Column('parqueo', sa.BOOLEAN(), nullable=False),
    sa.Column('mascotas', sa.BOOLEAN(), nullable=False),
    sa.Column('duchas', sa.BOOLEAN(), nullable=False),
    sa.Column('banos', sa.BOOLEAN(), nullable=False),
    sa.Column('imagen_post', sa.VARCHAR(length=255), nullable=True),
    sa.Column('date_posted', sa.DATETIME(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###
