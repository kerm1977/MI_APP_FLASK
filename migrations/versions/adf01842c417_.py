"""empty message

Revision ID: adf01842c417
Revises: fb4c013f5f4f
Create Date: 2025-04-12 06:52:33.576486

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'adf01842c417'
down_revision = 'fb4c013f5f4f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('contacto', schema=None) as batch_op:
        batch_op.add_column(sa.Column('avatar', sa.String(length=255), nullable=True))
        batch_op.alter_column('categoria',
               existing_type=sa.VARCHAR(length=50),
               type_=sa.String(length=100),
               existing_nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('contacto', schema=None) as batch_op:
        batch_op.alter_column('categoria',
               existing_type=sa.String(length=100),
               type_=sa.VARCHAR(length=50),
               existing_nullable=True)
        batch_op.drop_column('avatar')

    # ### end Alembic commands ###
