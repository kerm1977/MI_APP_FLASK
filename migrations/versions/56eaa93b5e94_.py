"""empty message

Revision ID: 56eaa93b5e94
Revises: 8a2c755b09a8
Create Date: 2025-04-08 17:25:08.293974

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '56eaa93b5e94'
down_revision = '8a2c755b09a8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('video', schema=None) as batch_op:
        batch_op.add_column(sa.Column('image_url', sa.String(length=200), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('video', schema=None) as batch_op:
        batch_op.drop_column('image_url')

    # ### end Alembic commands ###
