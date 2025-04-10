"""empty message

Revision ID: d6d5a13baf4f
Revises: 673e584af5fc
Create Date: 2025-04-09 19:16:33.850670

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd6d5a13baf4f'
down_revision = '673e584af5fc'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.drop_column('banos')
        batch_op.drop_column('etapa')
        batch_op.drop_column('coordinador')
        batch_op.drop_column('precio')
        batch_op.drop_column('capacidad')
        batch_op.drop_column('kilometros')
        batch_op.drop_column('lugar')
        batch_op.drop_column('duchas')
        batch_op.drop_column('dificultad')
        batch_op.drop_column('hora')
        batch_op.drop_column('altura')
        batch_op.drop_column('sinpe')
        batch_op.drop_column('finaliza')
        batch_op.drop_column('limite_pago')
        batch_op.drop_column('parqueo')
        batch_op.drop_column('mascotas')
        batch_op.drop_column('salida')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.add_column(sa.Column('salida', sa.DATETIME(), nullable=True))
        batch_op.add_column(sa.Column('mascotas', sa.VARCHAR(length=10), nullable=True))
        batch_op.add_column(sa.Column('parqueo', sa.VARCHAR(length=10), nullable=True))
        batch_op.add_column(sa.Column('limite_pago', sa.DATETIME(), nullable=True))
        batch_op.add_column(sa.Column('finaliza', sa.DATETIME(), nullable=True))
        batch_op.add_column(sa.Column('sinpe', sa.VARCHAR(length=50), nullable=True))
        batch_op.add_column(sa.Column('altura', sa.INTEGER(), nullable=True))
        batch_op.add_column(sa.Column('hora', sa.TIME(), nullable=True))
        batch_op.add_column(sa.Column('dificultad', sa.VARCHAR(length=50), nullable=True))
        batch_op.add_column(sa.Column('duchas', sa.VARCHAR(length=10), nullable=True))
        batch_op.add_column(sa.Column('lugar', sa.VARCHAR(length=100), nullable=True))
        batch_op.add_column(sa.Column('kilometros', sa.FLOAT(), nullable=True))
        batch_op.add_column(sa.Column('capacidad', sa.INTEGER(), nullable=True))
        batch_op.add_column(sa.Column('precio', sa.FLOAT(), nullable=True))
        batch_op.add_column(sa.Column('coordinador', sa.VARCHAR(length=50), nullable=True))
        batch_op.add_column(sa.Column('etapa', sa.INTEGER(), nullable=True))
        batch_op.add_column(sa.Column('banos', sa.VARCHAR(length=10), nullable=True))

    # ### end Alembic commands ###
